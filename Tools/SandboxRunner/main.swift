import Darwin
import Foundation
import LocalHarnessSandboxPolicy

private func fail(_ detail: String) -> Never {
    FileHandle.standardError.write(Data("fulmar-sandbox-runner: \(detail)\n".utf8))
    exit(125)
}

private func writeDiagnosticLine(after captured: Data, _ line: String) {
    if !captured.isEmpty, captured.last != 0x0A {
        FileHandle.standardError.write(Data([0x0A]))
    }
    FileHandle.standardError.write(Data("\(line)\n".utf8))
}

/// Makes the exact child process group created below a lease on the runner's
/// parent. This is the macOS
/// equivalent of the `--die-with-parent` contract accepted from DSH: normal
/// termination is forwarded to the complete group and escalates to SIGKILL;
/// an unexpected parent exit follows the same bounded path.
private final class RunnerLifecycleSupervisor {
    private let parentPID: pid_t
    private let queue = DispatchQueue(label: "app.localharness.sandbox-lifecycle", qos: .userInitiated)
    private var parentSource: DispatchSourceProcess?
    private var signalSources: [DispatchSourceSignal] = []
    private var processGroup: pid_t?
    private var pendingShutdownSignal: Int32?
    private var gracefulSignalSent = false
    private var installed = false
    private var cancelled = false

    init(parentPID: pid_t) {
        self.parentPID = parentPID
    }

    /// Arms every runner termination source before `posix_spawn`. A signal or
    /// parent exit that arrives before the child group is published is latched
    /// and applied synchronously by `attach(processGroup:)`; there is never a
    /// live child whose owner still has default terminating dispositions.
    func installBeforeSpawn() {
        queue.sync {
            guard !installed else { return }
            installed = true
            for signalNumber in [SIGINT, SIGTERM, SIGHUP] {
                // Dispatch signal sources require the ordinary disposition to
                // be ignored. The spawned child explicitly restores defaults.
                Darwin.signal(signalNumber, SIG_IGN)
                let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: queue)
                source.setEventHandler { [weak self] in self?.beginShutdown(forwarding: signalNumber) }
                signalSources.append(source)
                source.resume()
            }

            let source = DispatchSource.makeProcessSource(
                identifier: parentPID,
                eventMask: .exit,
                queue: queue
            )
            source.setEventHandler { [weak self] in self?.beginShutdown(forwarding: SIGTERM) }
            parentSource = source
            source.resume()

            // Close the registration race: if the original parent exited
            // before the process source became live, latch shutdown before a
            // sandbox child can be created.
            if getppid() != parentPID {
                requestShutdownLocked(forwarding: SIGTERM)
            }
        }
    }

    func attach(processGroup: pid_t) {
        queue.sync {
            guard processGroup > 0 else { return }
            guard self.processGroup == nil else {
                // The production path attaches once. Fail closed if a future
                // caller ever publishes a second owned group.
                _ = Darwin.kill(-processGroup, SIGKILL)
                return
            }
            self.processGroup = processGroup
            forwardPendingShutdownIfPossibleLocked()
        }
    }

    func cancel() {
        queue.sync {
            cancelled = true
            parentSource?.cancel()
            parentSource = nil
            for source in signalSources { source.cancel() }
            signalSources.removeAll()
        }
    }

    private func beginShutdown(forwarding signalNumber: Int32) {
        requestShutdownLocked(forwarding: signalNumber)
    }

    private func requestShutdownLocked(forwarding signalNumber: Int32) {
        guard !cancelled else { return }
        if pendingShutdownSignal == nil {
            pendingShutdownSignal = signalNumber == SIGINT ? SIGINT : SIGTERM
        }
        forwardPendingShutdownIfPossibleLocked()
    }

    private func forwardPendingShutdownIfPossibleLocked() {
        guard !cancelled,
              !gracefulSignalSent,
              let processGroup,
              let pendingShutdownSignal else { return }
        gracefulSignalSent = true
        _ = Darwin.kill(-processGroup, pendingShutdownSignal)
        queue.asyncAfter(deadline: .now() + .seconds(1)) { [weak self] in
            guard let self,
                  !self.cancelled,
                  let processGroup = self.processGroup else { return }
            _ = Darwin.kill(-processGroup, SIGKILL)
        }
    }
}

private let originalParentPID = getppid()

#if DEBUG
private let spawnBoundaryMarkerKey = "LOCAL_HARNESS_TEST_SPAWN_BOUNDARY_MARKER"
private let spawnBoundaryReleaseKey = "LOCAL_HARNESS_TEST_SPAWN_BOUNDARY_RELEASE"

/// Debug-only deterministic seam for the spawn-boundary cancellation test.
/// Production builds contain neither these environment names nor this pause.
private func pauseAtSpawnBoundaryForTesting(processGroup: pid_t) {
    let parentEnvironment = ProcessInfo.processInfo.environment
    guard let marker = parentEnvironment[spawnBoundaryMarkerKey],
          let release = parentEnvironment[spawnBoundaryReleaseKey],
          marker != release,
          marker.hasPrefix("/private/tmp/localharness-spawn-boundary-"),
          release.hasPrefix("/private/tmp/localharness-spawn-boundary-"),
          marker.utf8.count <= 4_096,
          release.utf8.count <= 4_096,
          !marker.contains("\0"),
          !release.contains("\0") else { return }
    let fileManager = FileManager.default
    guard fileManager.createFile(
        atPath: marker,
        contents: Data("\(processGroup)\n".utf8),
        attributes: [.posixPermissions: 0o600]
    ) else { return }
    let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
    while !fileManager.fileExists(atPath: release),
          DispatchTime.now().uptimeNanoseconds < deadline {
        usleep(5_000)
    }
}
#endif

private let mcpGuardMarkerKeys: Set<String> = [
    "LOCAL_HARNESS_MCP_GUARD_CHILD",
    "LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS",
    "LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP",
    "LOCAL_HARNESS_MCP_GUARD_PLAN"
]
private let mcpGuardControlKeys: Set<String> = [
    "LOCAL_HARNESS_STRICT_LOCAL",
    "LOCAL_HARNESS_WORKSPACE_ROOTS",
    "LOCAL_HARNESS_READONLY_ROOTS",
    "LOCAL_HARNESS_SANDBOX_TEMP"
]
private let mcpGuardBaseKeys: Set<String> = ["HOME", "USER", "LOGNAME", "PATH", "LANG", "TMPDIR"]
private let mcpGuardPlatformKeys: Set<String> = ["__CF_USER_TEXT_ENCODING"]
private let mcpGuardForbiddenCredentialKeys: Set<String> = [
    "BASH_ENV", "ENV", "HOME", "IFS", "LANG", "LOGNAME", "NODE_OPTIONS", "PATH", "PERL5OPT",
    "PYTHONHOME", "PYTHONPATH", "RUBYOPT", "SHELL", "TMPDIR", "USER", "ZDOTDIR"
]

private struct MCPGuardBootstrapPlan: Decodable {
    struct Project: Decodable { let canonicalPath: String }
    let schemaVersion: Int
    let project: Project
    let workingDirectory: String
    let credentialVariables: [String]
}

private func canonicalExistingPath(_ path: String, directory: Bool, label: String) -> String {
    guard path.hasPrefix("/"), !path.contains("\0"), path.utf8.count <= 4_096 else {
        fail("\(label) is not an absolute bounded path")
    }
    let components = path.components(separatedBy: "/")
    guard path == "/" || (!path.hasSuffix("/") && components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })) else {
        fail("\(label) is not normalized")
    }
    guard let resolved = path.withCString({ Darwin.realpath($0, nil) }) else {
        fail("\(label) does not exist")
    }
    defer { free(resolved) }
    let canonical = String(cString: resolved)
    guard canonical == path else { fail("\(label) cannot traverse a symbolic link") }
    var metadata = stat()
    guard Darwin.lstat(canonical, &metadata) == 0,
          directory ? metadata.st_mode & S_IFMT == S_IFDIR : metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == geteuid() || metadata.st_uid == 0,
          metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
        fail("\(label) has unsafe ownership, type, or permissions")
    }
    return canonical
}

private func decodeCanonicalBase64URL(_ encoded: String) -> Data? {
    guard !encoded.isEmpty, encoded.utf8.count <= 4 * 1_024 * 1_024,
          encoded.unicodeScalars.allSatisfy({
              CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
          }) else { return nil }
    var base64 = encoded.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.utf8.count % 4
    if remainder != 0 { base64 += String(repeating: "=", count: 4 - remainder) }
    guard let data = Data(base64Encoded: base64), data.count <= 2 * 1_024 * 1_024 else { return nil }
    let canonical = data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return canonical == encoded ? data : nil
}

private func validateMCPGuardBootstrap(
    environment: [String: String],
    rootPaths: [String],
    readOnlyPaths: [String],
    tempPath: String,
    invocation: LocalHarnessSandboxInvocation
) -> Set<String>? {
    let presentMarkers = mcpGuardMarkerKeys.filter { environment[$0] != nil }
    guard !presentMarkers.isEmpty else { return nil }
    guard environment["LOCAL_HARNESS_MCP_GUARD_CHILD"] == "1",
          presentMarkers.count == mcpGuardMarkerKeys.count,
          environment["LOCAL_HARNESS_STRICT_LOCAL"] == "1",
          rootPaths.count == 1,
          readOnlyPaths.isEmpty,
          invocation.mode == .readOnly,
          let markerRootData = environment["LOCAL_HARNESS_MCP_GUARD_WORKSPACE_ROOTS"]?.data(using: .utf8),
          let markerRoots = try? JSONDecoder().decode([String].self, from: markerRootData),
          markerRoots == rootPaths,
          environment["LOCAL_HARNESS_MCP_GUARD_SANDBOX_TEMP"] == tempPath,
          environment["TMPDIR"] == tempPath,
          let encodedPlan = environment["LOCAL_HARNESS_MCP_GUARD_PLAN"],
          let planData = decodeCanonicalBase64URL(encodedPlan),
          let plan = try? JSONDecoder().decode(MCPGuardBootstrapPlan.self, from: planData),
          plan.schemaVersion == 1,
          plan.credentialVariables.count <= 12,
          Set(plan.credentialVariables).count == plan.credentialVariables.count else {
        fail("MCP guard bootstrap metadata is invalid")
    }

    let canonicalRoot = canonicalExistingPath(rootPaths[0], directory: true, label: "MCP project root")
    let canonicalWorkingDirectory = canonicalExistingPath(plan.workingDirectory, directory: true, label: "MCP working directory")
    let canonicalTemp = canonicalExistingPath(tempPath, directory: true, label: "MCP sandbox temp root")
    let rootPrefix = canonicalRoot.hasSuffix("/") ? canonicalRoot : canonicalRoot + "/"
    guard plan.project.canonicalPath == canonicalRoot,
          canonicalWorkingDirectory == FileManager.default.currentDirectoryPath,
          canonicalWorkingDirectory == canonicalRoot || canonicalWorkingDirectory.hasPrefix(rootPrefix),
          canonicalTemp == tempPath else {
        fail("MCP guard bootstrap paths do not match the reviewed activation plan")
    }

    let helper = canonicalExistingPath(
        CommandLine.arguments[0],
        directory: false,
        label: "sandbox helper"
    )
    func deletingLastComponent(_ value: String) -> String {
        guard let separator = value.lastIndex(of: "/"), separator != value.startIndex else { return "/" }
        return String(value[..<separator])
    }
    func appendingComponent(_ component: String, to root: String) -> String {
        root.hasSuffix("/") ? root + component : root + "/" + component
    }
    let macOSDirectory = deletingLastComponent(helper)
    let contents = deletingLastComponent(macOSDirectory)
    let expectedNode = canonicalExistingPath(
        appendingComponent("Resources/Runtime/node", to: contents),
        directory: false,
        label: "bundled MCP Node runtime"
    )
    let expectedRunner = canonicalExistingPath(
        appendingComponent(
            "Resources/Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded/stdio-guard-runner.mjs",
            to: contents
        ),
        directory: false,
        label: "bundled MCP guard runner"
    )
    guard invocation.command == [expectedNode, expectedRunner] else {
        fail("MCP guard attempted to substitute its bundled Node runner")
    }

    for name in plan.credentialVariables {
        guard name.range(of: #"^[A-Z][A-Z0-9_]{0,63}$"#, options: .regularExpression) != nil,
              !mcpGuardForbiddenCredentialKeys.contains(name),
              !name.hasPrefix("DSH_"), !name.hasPrefix("DYLD_"), !name.hasPrefix("LD_"),
              !name.hasPrefix("LOCAL_HARNESS_"),
              let value = environment[name], !value.isEmpty, value.utf8.count <= 1_048_576,
              !value.contains("\0"), !value.contains("\r"), !value.contains("\n") else {
            fail("MCP guard credential environment is missing or invalid")
        }
    }
    for name in mcpGuardBaseKeys {
        guard let value = environment[name], !value.isEmpty, value.utf8.count <= 16_384,
              !value.contains("\0"), !value.contains("\r"), !value.contains("\n") else {
            fail("MCP guard base environment is missing or invalid")
        }
    }
    let allowed = mcpGuardMarkerKeys
        .union(mcpGuardControlKeys)
        .union(mcpGuardBaseKeys)
        .union(mcpGuardPlatformKeys)
        .union(plan.credentialVariables)
    guard Set(environment.keys).isSubset(of: allowed) else {
        fail("MCP guard environment contained unreviewed host values")
    }
    return allowed
}

let strictLocal = ProcessInfo.processInfo.environment["LOCAL_HARNESS_STRICT_LOCAL"] == "1"
let bootstrapEnvironment = ProcessInfo.processInfo.environment
guard let rootsData = bootstrapEnvironment["LOCAL_HARNESS_WORKSPACE_ROOTS"]?.data(using: .utf8),
      let rootPaths = try? JSONDecoder().decode([String].self, from: rootsData),
      !rootPaths.isEmpty,
      rootPaths.allSatisfy({ $0.hasPrefix("/") && !$0.contains("\0") }) else {
    fail("approved workspace roots are missing or invalid")
}
let approvedRoots = rootPaths.map { URL(fileURLWithPath: $0, isDirectory: true) }
guard let readOnlyData = bootstrapEnvironment["LOCAL_HARNESS_READONLY_ROOTS"]?.data(using: .utf8),
      let readOnlyPaths = try? JSONDecoder().decode([String].self, from: readOnlyData),
      readOnlyPaths.count <= 8,
      readOnlyPaths.allSatisfy({ $0.hasPrefix("/") && !$0.contains("\0") }) else {
    fail("approved read-only roots are missing or invalid")
}
let approvedReadOnlyRoots = readOnlyPaths.map { URL(fileURLWithPath: $0, isDirectory: true) }
guard let tempPath = bootstrapEnvironment["LOCAL_HARNESS_SANDBOX_TEMP"], tempPath.hasPrefix("/"), !tempPath.contains("\0") else {
    fail("private sandbox temp root is missing or invalid")
}
let invocation: LocalHarnessSandboxInvocation
do {
    invocation = try LocalHarnessSandboxInvocation(
        arguments: Array(CommandLine.arguments.dropFirst()),
        strictLocal: strictLocal,
        temporaryDirectory: URL(fileURLWithPath: tempPath, isDirectory: true),
        approvedWorkspaceRoots: approvedRoots,
        approvedReadOnlyRoots: approvedReadOnlyRoots
    )
} catch {
    fail(error.localizedDescription)
}

let mcpGuardAllowedEnvironment = validateMCPGuardBootstrap(
    environment: bootstrapEnvironment,
    rootPaths: rootPaths,
    readOnlyPaths: readOnlyPaths,
    tempPath: tempPath,
    invocation: invocation
)

var environment = ProcessInfo.processInfo.environment
#if DEBUG
environment.removeValue(forKey: spawnBoundaryMarkerKey)
environment.removeValue(forKey: spawnBoundaryReleaseKey)
#endif
if let allowed = mcpGuardAllowedEnvironment {
    environment = Dictionary(uniqueKeysWithValues: environment.compactMap { key, value in
        allowed.contains(key) ? (key, value) : nil
    })
} else {
    for key in [
        "LOCAL_HARNESS_AUTH_TOKEN", "LOCAL_HARNESS_INSTANCE_NONCE",
        "LOCAL_HARNESS_CREDENTIAL_PLUGIN", "LOCAL_HARNESS_CREDENTIAL_HELPER",
        "LOCAL_HARNESS_MCP_PLUGIN", "LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN",
        "LOCAL_HARNESS_PERFORMANCE_PLUGIN", "LOCAL_HARNESS_RUNTIME_ROOT",
        "LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER",
        "LOCAL_HARNESS_SANDBOX_HELPER", "LOCAL_HARNESS_WORKSPACE_ROOTS",
        "LOCAL_HARNESS_READONLY_ROOTS", "LOCAL_HARNESS_SANDBOX_TEMP", "OLLAMA_API_KEY"
    ] { environment.removeValue(forKey: key) }
}

private let lifecycle = RunnerLifecycleSupervisor(parentPID: originalParentPID)
lifecycle.installBeforeSpawn()
let outcome: BoundedProcessGroupResult
do {
    outcome = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/usr/bin/sandbox-exec"),
        arguments: ["-p", invocation.profile, "--"] + invocation.command,
        environment: environment,
        maximumStderrBytes: 64 * 1_024,
        deadline: 7_200,
        onSpawn: { processGroup in
            #if DEBUG
            pauseAtSpawnBoundaryForTesting(processGroup: processGroup)
            #endif
            lifecycle.attach(processGroup: processGroup)
        }
    )
} catch {
    lifecycle.cancel()
    fail("could not start or supervise sandbox-exec")
}
lifecycle.cancel()
FileHandle.standardError.write(outcome.stderr)

if let limit = outcome.limit {
    switch limit {
    case .stderrBytes(let maximum):
        writeDiagnosticLine(
            after: outcome.stderr,
            "fulmar-sandbox-runner: child stderr exceeded \(maximum) bytes; output was truncated and the exact process group was stopped"
        )
    case .deadline(let seconds):
        writeDiagnosticLine(
            after: outcome.stderr,
            "fulmar-sandbox-runner: child exceeded the \(Int(seconds))-second hard deadline; the exact process group was stopped"
        )
    }
    exit(125)
}

if String(decoding: outcome.stderr, as: UTF8.self).localizedCaseInsensitiveContains("operation not permitted") {
    writeDiagnosticLine(after: outcome.stderr, "permission denied by Fulmar tool sandbox")
}

if let signal = outcome.terminationSignal {
    exit(128 + signal)
}
exit(outcome.exitStatus ?? 125)
