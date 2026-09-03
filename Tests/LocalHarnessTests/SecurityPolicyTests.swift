import Foundation
import CryptoKit
import Darwin
import LocalHarnessApplicationSupportAdmission
import LocalHarnessSandboxPolicy
import Testing
@testable import LocalHarness

private let boundedRunnerTestEnvironment = ["PATH": "/usr/bin:/bin"]

private func makeSecureAttestationTestRoot(prefix: String) throws -> URL {
    guard !prefix.isEmpty, prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }),
          let account = getpwuid(geteuid()),
          let home = account.pointee.pw_dir else {
        throw CocoaError(.fileNoSuchFile)
    }
    let root = URL(fileURLWithPath: String(cString: home), isDirectory: true)
        .appendingPathComponent("Library/Caches", isDirectory: true)
        .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return root
}

private func makeSecureNonUsersSandboxHome() throws -> URL {
    let required = confstr(_CS_DARWIN_USER_CACHE_DIR, nil, 0)
    guard required > 1, required <= 4_096 else {
        throw CocoaError(.fileNoSuchFile)
    }
    var bytes = [CChar](repeating: 0, count: required)
    let copied = bytes.withUnsafeMutableBufferPointer { buffer in
        confstr(_CS_DARWIN_USER_CACHE_DIR, buffer.baseAddress, required)
    }
    guard copied == required else { throw CocoaError(.fileReadUnknown) }
    let path = String(cString: bytes)
    guard let canonical = Darwin.realpath(path, nil) else {
        throw CocoaError(.fileReadUnknown)
    }
    defer { Darwin.free(canonical) }
    let cache = URL(
        fileURLWithPath: String(cString: canonical),
        isDirectory: true
    )
    let home = cache.appendingPathComponent(
        "fulmar-sandbox-portable-home-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(
        at: home,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: home.path
    )
    return home
}

private func addSandboxReadACL(to url: URL) throws {
    guard let account = getpwuid(geteuid()) else {
        throw CocoaError(.fileReadUnknown)
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = [
        "+a",
        "\(String(cString: account.pointee.pw_name)) allow read",
        url.path
    ]
    process.environment = boundedRunnerTestEnvironment
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    guard boundedTestWaitForExit(process, timeout: 5),
          process.terminationReason == .exit,
          process.terminationStatus == 0 else {
        throw CocoaError(.fileWriteUnknown)
    }
}

private func debugSandboxRunnerExecutable() -> URL? {
    let sourceRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let buildCandidate = sourceRoot.appendingPathComponent(".build/debug/LocalHarnessSandboxRunner")
    if FileManager.default.isExecutableFile(atPath: buildCandidate.path) { return buildCandidate }

    var cursor = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
    while cursor.path != "/" {
        let candidate = cursor.appendingPathComponent("LocalHarnessSandboxRunner")
        if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        cursor.deleteLastPathComponent()
    }
    return nil
}

private func waitForSandboxCondition(
    timeout: TimeInterval,
    _ condition: () -> Bool
) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return true }
        usleep(10_000)
    }
    return condition()
}

@Test func nativeTestLauncherIsolatesHomeTempStateAndAmbientCredentials() throws {
    let environment = ProcessInfo.processInfo.environment
    let rootPath = try #require(environment["LOCAL_HARNESS_SWIFT_TEST_ISOLATION_ROOT"])
    let root = URL(fileURLWithPath: rootPath, isDirectory: true).standardizedFileURL
    let expectedHome = root.appendingPathComponent("home", isDirectory: true).standardizedFileURL
    let expectedTemporary = root.appendingPathComponent("tmp", isDirectory: true).standardizedFileURL

    #expect(URL(fileURLWithPath: environment["HOME"] ?? "").standardizedFileURL == expectedHome)
    #expect(URL(fileURLWithPath: environment["CFFIXED_USER_HOME"] ?? "").standardizedFileURL == expectedHome)
    #expect(URL(fileURLWithPath: environment["TMPDIR"] ?? "").standardizedFileURL == expectedTemporary)
    #expect(FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL == expectedHome)
    let foundationTemporary = FileManager.default.temporaryDirectory.standardizedFileURL
    if foundationTemporary != expectedTemporary {
        // On macOS, SwiftPM's testing helper may cache the per-user Darwin
        // temporary directory before the test bundle observes TMPDIR. That
        // location is OS-owned and private; it is never Fulmar support state.
        var metadata = stat()
        #expect(Darwin.lstat(foundationTemporary.path, &metadata) == 0)
        #expect(metadata.st_uid == geteuid())
        #expect(metadata.st_mode & (S_IWGRP | S_IWOTH) == 0)
        #expect(!foundationTemporary.path.contains("/Library/Application Support/"))
    }

    for forbidden in [
        "SSH_AUTH_SOCK", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "LD_PRELOAD", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OLLAMA_API_KEY",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN",
        "CODEX_HOME", "SDKROOT", "DEVELOPER_DIR", "CLANG_MODULE_CACHE_PATH",
        "SWIFTPM_MODULECACHE_OVERRIDE"
    ] {
        // SwiftPM may add its own Testing framework loader path after the
        // wrapper starts. The security contract is that no caller-controlled
        // value crosses the clean-environment boundary.
        #expect(environment[forbidden] != "fulmar-forbidden-ambient-value")
    }

    let controller = HarnessController()
    let support = controller.diagnosticsDirectory().standardizedFileURL
    // The signed test HOME lives below macOS's `/tmp` alias. Foundation
    // canonicalizes `/private/tmp` to that symlinked spelling, while production
    // Application Support admission deliberately rejects every symlink in its
    // ancestry. The correct test-host result is therefore a fail-closed sink,
    // never a write to the real user's Application Support directory.
    #expect(support == ApplicationSupportRootAdmission.unavailableSink.standardizedFileURL)
    #expect(!FileManager.default.fileExists(
        atPath: support.appendingPathComponent("services.log").path
    ))
    let isolatedParent = expectedHome.appendingPathComponent(
        "Library/Application Support",
        isDirectory: true
    )
    #expect(FileManager.default.fileExists(atPath: isolatedParent.path))
    #expect(isolatedParent.path.hasPrefix(root.path + "/"))
}

@Test func boundedProcessGroupRunnerDiscardsStandardOutputWithoutBorrowingAFileHandle() throws {
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "printf 'discarded'; exit 9"],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 1,
        discardStandardOutput: true
    )
    #expect(result.exitStatus == 9)
    #expect(result.limit == nil)
    #expect(result.stderr.isEmpty)

    #expect(throws: BoundedProcessGroupRunnerError.invalidConfiguration) {
        _ = try BoundedProcessGroupRunner.run(
            executable: URL(fileURLWithPath: "/bin/true"),
            arguments: [],
            environment: boundedRunnerTestEnvironment,
            maximumStderrBytes: 4_096,
            deadline: 1,
            standardOutputDescriptor: STDOUT_FILENO,
            discardStandardOutput: true
        )
    }
}

@Test func boundedProcessGroupRunnerPreservesSmallStderrAndExactExitStatus() throws {
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "printf 'sandbox-exec: operation not permitted\\n' >&2; exit 7"],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 1_024,
        deadline: 2
    )

    #expect(result.exitStatus == 7)
    #expect(result.terminationSignal == nil)
    #expect(result.stderr == Data("sandbox-exec: operation not permitted\n".utf8))
    #expect(!result.stderrWasTruncated)
    #expect(result.limit == nil)
}

@Test func boundedProcessGroupRunnerCapsFiniteStderrBurstBeforeExit() throws {
    let started = Date()
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
            "-c",
            "i=0; while [ \"$i\" -lt 7000 ]; do printf 0123456789 >&2; i=$((i + 1)); done"
        ],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 3,
        terminationGrace: 0.05
    )

    #expect(Date().timeIntervalSince(started) < 2)
    #expect(result.limit == .stderrBytes(4_096))
    #expect(result.stderrWasTruncated)
    #expect(result.stderr.count == 4_096)
    #expect(result.stderr.allSatisfy { (48...57).contains($0) })
}

@Test func boundedProcessGroupRunnerKillsEndlessTermResistantWriterButNotSibling() throws {
    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
    unrelated.arguments = ["30"]
    try unrelated.run()
    defer {
        if unrelated.isRunning { _ = Darwin.kill(unrelated.processIdentifier, SIGKILL) }
        #expect(boundedTestWaitForExit(unrelated, timeout: 3))
    }

    let started = Date()
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "trap '' TERM; while :; do printf 0123456789 >&2; done"],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 3,
        terminationGrace: 0.05
    )

    #expect(Date().timeIntervalSince(started) < 2)
    #expect(result.limit == .stderrBytes(4_096))
    #expect(result.stderrWasTruncated)
    #expect(result.stderr.count == 4_096)
    #expect(unrelated.isRunning)
}

@Test func boundedProcessGroupRunnerKillsDescendantHoldingPipeAfterLeaderExit() throws {
    let started = Date()
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
            "-c",
            "(trap '' TERM; while :; do printf descendant >&2; done) & exit 0"
        ],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 3,
        terminationGrace: 0.05
    )

    #expect(Date().timeIntervalSince(started) < 2)
    #expect(result.exitStatus == 0)
    #expect(result.limit == .stderrBytes(4_096))
    #expect(result.stderrWasTruncated)
    #expect(result.stderr.count == 4_096)
}

@Test func boundedProcessGroupRunnerDoesNotHangOnEscapedDescendantHoldingPipe() throws {
    let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(
        "bounded-runner-escaped-descendant-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let escapedPIDFile = root.appendingPathComponent("escaped.pid")
    var escapedPID: pid_t = 0
    defer {
        if escapedPID <= 1,
           let contents = try? String(contentsOf: escapedPIDFile, encoding: .utf8),
           let parsed = pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines)) {
            escapedPID = parsed
        }
        if escapedPID > 1 { _ = Darwin.kill(escapedPID, SIGKILL) }
        if escapedPID > 1 {
            _ = waitForSandboxCondition(timeout: 2) {
                Darwin.kill(escapedPID, 0) != 0 && errno == ESRCH
            }
        }
    }

    let program = #"""
    use POSIX qw(setsid);
    my $pid = fork();
    die "fork failed" unless defined $pid;
    if ($pid == 0) {
        setsid() or die "setsid failed";
        open(my $pid_file, '>', $ARGV[0]) or die "pid file failed";
        print $pid_file "$$\n";
        close($pid_file);
        $SIG{TERM} = 'IGNORE';
        $SIG{PIPE} = 'IGNORE';
        alarm 5;
        while (1) { print STDERR 'escaped-descendant'; }
    }
    exit 0;
    """#
    let started = Date()
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/usr/bin/perl"),
        arguments: ["-MPOSIX", "-e", program, escapedPIDFile.path],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 1,
        terminationGrace: 0.05
    )
    let duration = Date().timeIntervalSince(started)
    if let contents = try? String(contentsOf: escapedPIDFile, encoding: .utf8) {
        escapedPID = pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
    }

    #expect(duration < 2)
    #expect(result.exitStatus == 0)
    #expect(result.limit == .stderrBytes(4_096))
    #expect(result.stderrWasTruncated)
    #expect(result.stderr.count == 4_096)
    #expect(escapedPID > 1)
}

@Test func boundedProcessGroupRunnerEnforcesShortDeadlineWithoutOutput() throws {
    let started = Date()
    let result = try BoundedProcessGroupRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: ["-c", "trap '' TERM; while :; do /bin/sleep 1; done"],
        environment: boundedRunnerTestEnvironment,
        maximumStderrBytes: 4_096,
        deadline: 0.1,
        terminationGrace: 0.05
    )

    #expect(Date().timeIntervalSince(started) < 2)
    #expect(result.limit == .deadline(0.1))
    #expect(!result.stderrWasTruncated)
    #expect(result.stderr.isEmpty)
}

@Test func startupSandboxBoundaryProbeBoundsAndReapsAHungHelper() throws {
    let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(
        "sandbox-boundary-deadline-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executable = root.appendingPathComponent("hung-sandbox-helper")
    try Data("#!/bin/sh\ntrap '' TERM INT HUP\nwhile :; do /bin/sleep 1; done\n".utf8)
        .write(to: executable, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)

    var processGroup: pid_t = 0
    let started = Date()
    #expect(throws: SandboxBoundaryProbeProcessError.resourceLimit) {
        _ = try SandboxBoundaryProbeProcess.run(
            executable: executable,
            arguments: [],
            currentDirectory: root,
            environment: boundedRunnerTestEnvironment,
            deadline: 0.1,
            terminationGrace: 0.05,
            onSpawn: { processGroup = $0 }
        )
    }
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(processGroup > 1)
    #expect(waitForSandboxCondition(timeout: 2) {
        Darwin.kill(-processGroup, 0) != 0 && errno == ESRCH
    })

    #expect(try SandboxBoundaryProbeProcess.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        // Validate the kernel working directory by relative lookup. Textual
        // paths can legitimately differ across macOS's /var -> /private/var
        // alias, and PWD is intentionally absent from the minimal child env.
        arguments: ["-c", "test -x ./hung-sandbox-helper"],
        currentDirectory: root,
        environment: boundedRunnerTestEnvironment,
        deadline: 1
    ) == 0)
}

@Test func sandboxRunnerLatchesCancellationAtSpawnBoundaryAndReapsExactGroup() throws {
    let fileManager = FileManager.default
    let root = URL(
        fileURLWithPath: "/private/tmp/localharness-spawn-boundary-\(UUID().uuidString)",
        isDirectory: true
    )
    let workspace = root.appendingPathComponent("workspace", isDirectory: true)
    let sandboxTemp = workspace.appendingPathComponent(".private-tmp", isDirectory: true)
    let marker = root.appendingPathComponent("spawned")
    let release = root.appendingPathComponent("release")
    try fileManager.createDirectory(at: sandboxTemp, withIntermediateDirectories: true)
    for directory in [root, workspace, sandboxTemp] {
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    defer { try? fileManager.removeItem(at: root) }

    let executable = try #require(debugSandboxRunnerExecutable())
    let runner = Process()
    let runnerError = Pipe()
    runner.executableURL = executable
    runner.currentDirectoryURL = workspace
    runner.standardOutput = FileHandle.nullDevice
    runner.standardError = runnerError
    runner.arguments = [
        "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc",
        "--die-with-parent", "--tmpfs", "/tmp", "--bind", workspace.path, workspace.path,
        "--", "/bin/bash", "-c",
        "trap '' TERM INT HUP; while :; do /bin/sleep 1; done"
    ]
    runner.environment = [
        "PATH": "/usr/bin:/bin",
        "LOCAL_HARNESS_STRICT_LOCAL": "1",
        "LOCAL_HARNESS_WORKSPACE_ROOTS": "[\"\(workspace.path)\"]",
        "LOCAL_HARNESS_READONLY_ROOTS": "[]",
        "LOCAL_HARNESS_SANDBOX_TEMP": sandboxTemp.path,
        "LOCAL_HARNESS_TEST_SPAWN_BOUNDARY_MARKER": marker.path,
        "LOCAL_HARNESS_TEST_SPAWN_BOUNDARY_RELEASE": release.path
    ]

    var processGroup: pid_t = 0
    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/bin/sleep")
    unrelated.arguments = ["30"]
    defer {
        _ = fileManager.createFile(atPath: release.path, contents: Data())
        if runner.isRunning { _ = Darwin.kill(runner.processIdentifier, SIGKILL) }
        if processGroup > 1 { _ = Darwin.kill(-processGroup, SIGKILL) }
        #expect(boundedTestWaitForExit(runner, timeout: 3))
        if unrelated.isRunning { _ = Darwin.kill(unrelated.processIdentifier, SIGKILL) }
        #expect(boundedTestWaitForExit(unrelated, timeout: 3))
    }

    try runner.run()
    try #require(waitForSandboxCondition(timeout: 3) {
        fileManager.fileExists(atPath: marker.path)
    })
    let markerText = try String(contentsOf: marker, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    processGroup = try #require(pid_t(markerText))
    #expect(processGroup > 1)
    #expect(Darwin.kill(-processGroup, 0) == 0)

    try unrelated.run()
    #expect(Darwin.kill(runner.processIdentifier, SIGTERM) == 0)
    usleep(100_000)
    // The debug seam is still between posix_spawn and group publication. The
    // pre-armed runner must remain alive with cancellation latched.
    #expect(runner.isRunning)
    #expect(Darwin.kill(-processGroup, 0) == 0)
    #expect(fileManager.createFile(atPath: release.path, contents: Data()))

    try #require(waitForSandboxCondition(timeout: 4) { !runner.isRunning })
    #expect(boundedTestWaitForExit(runner, timeout: 3))
    #expect(runner.terminationReason == .exit)
    #expect(waitForSandboxCondition(timeout: 2) {
        Darwin.kill(-processGroup, 0) != 0 && errno == ESRCH
    })
    #expect(unrelated.isRunning)
}

@Test func secureTokensUseAtLeast256BitsAndURLSafeEncoding() throws {
    let first = try SecureTokenGenerator.generate()
    let second = try SecureTokenGenerator.generate()
    #expect(first.count >= 43)
    #expect(first != second)
    #expect(first.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil)
}

@Test func runtimeAuthenticationInputIsOwnerOnlyUnlinkedAndOneShot() throws {
    let token = "swift-runtime-auth-token-0123456789_ABCDE"
    let nonce = "swift-runtime-instance-nonce-0123456789"
    let expected = try RuntimeAuthenticationInput.frame(authToken: token, nonce: nonce)
    var pathnameWasAbsentBeforeWrite = false
    let input = try RuntimeAuthenticationInput(
        authToken: token,
        nonce: nonce,
        beforeWriteForTesting: { path in
            var metadata = stat()
            errno = 0
            pathnameWasAbsentBeforeWrite = Darwin.lstat(path, &metadata) != 0 && errno == ENOENT
        }
    )
    #expect(pathnameWasAbsentBeforeWrite)
    let handle = try input.takeForLaunch()
    defer { try? handle.close() }

    var metadata = stat()
    #expect(Darwin.fstat(handle.fileDescriptor, &metadata) == 0)
    #expect(metadata.st_mode & S_IFMT == S_IFREG)
    #expect(metadata.st_nlink == 0)
    #expect(metadata.st_uid == Darwin.geteuid())
    #expect(metadata.st_mode & 0o777 == 0o600)
    #expect(metadata.st_size == off_t(expected.count))
    #expect(Darwin.lseek(handle.fileDescriptor, 0, SEEK_CUR) == 0)

    let unrelated = Process()
    unrelated.executableURL = URL(fileURLWithPath: "/bin/sh")
    unrelated.arguments = [
        "-c", "test ! -e \"/dev/fd/$1\"", "fulmar-runtime-auth-fd-probe",
        String(handle.fileDescriptor)
    ]
    unrelated.environment = ["HOME": FileManager.default.homeDirectoryForCurrentUser.path, "PATH": "/usr/bin:/bin"]
    unrelated.standardInput = FileHandle.nullDevice
    unrelated.standardOutput = FileHandle.nullDevice
    unrelated.standardError = FileHandle.nullDevice
    try unrelated.run()
    #expect(boundedTestWaitForExit(unrelated, timeout: 3))
    #expect(unrelated.terminationReason == .exit)
    #expect(unrelated.terminationStatus == 0)

    #expect(try handle.readToEnd() == expected)
    #expect(throws: RuntimeSecurityError.self) {
        _ = try input.takeForLaunch()
    }
}

@Test func runtimeAuthenticationInputRejectsMalformedOrOversizedMaterial() {
    #expect(throws: RuntimeSecurityError.self) {
        _ = try RuntimeAuthenticationInput(authToken: "short", nonce: String(repeating: "n", count: 32))
    }
    #expect(throws: RuntimeSecurityError.self) {
        _ = try RuntimeAuthenticationInput(
            authToken: String(repeating: "a", count: 129),
            nonce: String(repeating: "n", count: 32)
        )
    }
    #expect(throws: RuntimeSecurityError.self) {
        _ = try RuntimeAuthenticationInput(
            authToken: String(repeating: "a", count: 32),
            nonce: "invalid:nonce-material-0123456789"
        )
    }
}

@Test func childEnvironmentDoesNotLeakUnrelatedParentValues() {
    let environment = ChildProcessEnvironment.make(nodeBin: "/example/node", additions: ["TEST_AUTH": "private"])
    #expect(environment["TEST_AUTH"] == "private")
    #expect(environment["PATH"]?.hasPrefix("/example/node:") == true)
    #expect(environment["DSH_TELEMETRY_MODE"] == "DISABLED")
    #expect(environment["OPENAI_API_KEY"] == nil)
    #expect(environment["ANTHROPIC_API_KEY"] == nil)
    #expect(environment["AWS_SECRET_ACCESS_KEY"] == nil)
    #expect(environment["OLLAMA_API_KEY"] == nil)
    #expect(environment["SSH_AUTH_SOCK"] == nil)
}

@Test func harnessEnvironmentAddsLocalOllamaMarkerOnlyAfterNativeAvailabilityProof() {
    let additions = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true
    )
    #expect(additions["OLLAMA_API_KEY"] == nil)
    #expect(additions["LOCAL_HARNESS_AUTH_TOKEN"] == nil)
    #expect(additions["LOCAL_HARNESS_INSTANCE_NONCE"] == nil)
    #expect(additions["LOCAL_HARNESS_CREDENTIAL_PLUGIN"] == "/plugin")
    #expect(additions["LOCAL_HARNESS_CREDENTIAL_HOME"] == FileManager.default.homeDirectoryForCurrentUser.path)
    #expect(additions["LOCAL_HARNESS_MCP_PLUGIN"] == "/mcp-plugin")
    #expect(additions["LOCAL_HARNESS_CLIENT_SECURITY_PLUGIN"] == "/client-security-plugin")
    #expect(additions["LOCAL_HARNESS_PERFORMANCE_PLUGIN"] == "/performance-plugin")
    #expect(additions["LOCAL_HARNESS_SANDBOX_HELPER"] == "/sandbox")
    #expect(additions["LOCAL_HARNESS_STRICT_LOCAL"] == "1")
    #expect(additions["LOCAL_HARNESS_WORKSPACE_ROOTS"] == "[]")
    #expect(additions["LOCAL_HARNESS_READONLY_ROOTS"] == "[]")
    #expect(additions["LOCAL_HARNESS_PERFORMANCE_PROFILE"] == "balanced")
    #expect(additions["LOCAL_HARNESS_CONTEXT_WINDOW_TOKENS"] == "49152")
    #expect(additions["LOCAL_HARNESS_MAX_OUTPUT_TOKENS"] == "8192")
    #expect(additions["LOCAL_HARNESS_KEEP_ALIVE_SECONDS"] == "600")
    #expect(additions["LOCAL_HARNESS_PERFORMANCE_PROFILES"] == PerformanceProfile.runtimeCatalogJSON)
    #expect(additions["LOCAL_HARNESS_CONTEXT_ENFORCEMENT"] == nil)
    #expect(additions["LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER"] == nil)
    #expect(additions["OPENAI_API_KEY"] == nil)
    #expect(additions["DEEPSEEK_API_KEY"] == nil)

    let ownedLocal = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        localOllamaAvailable: true
    )
    #expect(ownedLocal["OLLAMA_API_KEY"] == "local-ollama")

    let acceptanceLocal = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        localOllamaAvailable: true,
        forbidCredentialHelper: true
    )
    #expect(acceptanceLocal["OLLAMA_API_KEY"] == "local-ollama")
    #expect(acceptanceLocal["LOCAL_HARNESS_FORBID_CREDENTIAL_HELPER"] == "1")

    let configured = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        workspaceRootsJSON: "[\"/workspace\"]",
        readOnlyRootsJSON: "[\"/skills\"]",
        mcpCatalogPath: "/private/catalog.json",
        applicationSupportRoot: "/private/app-support/Local Harness",
        performanceTelemetryFile: "/private/app-support/Local Harness/PerformanceTelemetry/performance-telemetry.json",
        thermalWorkloadPolicyFile: "/private/app-support/Local Harness/PerformanceTelemetry/thermal-workload-policy.json"
    )
    #expect(configured["LOCAL_HARNESS_WORKSPACE_ROOTS"] == "[\"/workspace\"]")
    #expect(configured["LOCAL_HARNESS_READONLY_ROOTS"] == "[\"/skills\"]")
    #expect(configured["LOCAL_HARNESS_MCP_CATALOG"] == "/private/catalog.json")
    #expect(configured["LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT"] == "/private/app-support/Local Harness")
    #expect(configured["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE"] == "/private/app-support/Local Harness/PerformanceTelemetry/performance-telemetry.json")
    #expect(configured["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER"] == "/helper")
    #expect(configured["LOCAL_HARNESS_THERMAL_POLICY_FILE"] == "/private/app-support/Local Harness/PerformanceTelemetry/thermal-workload-policy.json")

    let partialTelemetry = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        applicationSupportRoot: "/private/app-support/Local Harness"
    )
    #expect(partialTelemetry["LOCAL_HARNESS_APPLICATION_SUPPORT_ROOT"] == nil)
    #expect(partialTelemetry["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_FILE"] == nil)
    #expect(partialTelemetry["LOCAL_HARNESS_PERFORMANCE_TELEMETRY_LOCK_HELPER"] == nil)

    let deep = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        localOllamaAvailable: true,
        performanceProfile: .deep,
        activeProvider: ProviderID("ollama"),
        contextEnforcementRoute: .init(
            provider: ProviderID("ollama"),
            model: ModelID("qwen3.8:27b-mlx")
        )
    )
    #expect(deep["LOCAL_HARNESS_PERFORMANCE_PROFILE"] == "deep")
    #expect(deep["LOCAL_HARNESS_CONTEXT_WINDOW_TOKENS"] == "65536")
    #expect(deep["LOCAL_HARNESS_MAX_OUTPUT_TOKENS"] == "16384")
    #expect(deep["LOCAL_HARNESS_KEEP_ALIVE_SECONDS"] == "1200")
    #expect(deep["OLLAMA_API_KEY"] == "local-ollama")
    #expect(deep["LOCAL_HARNESS_CONTEXT_ENFORCEMENT"] == #"{"contextWindowTokens":65536,"model":"qwen3.8:27b-mlx","provider":"ollama"}"#)

    let compatibility = HarnessProcessEnvironment.additions(
        credentialPlugin: "/plugin",
        mcpPlugin: "/mcp-plugin",
        clientSecurityPlugin: "/client-security-plugin",
        performancePlugin: "/performance-plugin",
        credentialHelper: "/helper",
        sandboxHelper: "/sandbox",
        strictLocal: true,
        localOllamaAvailable: true,
        performanceProfile: .compatibility,
        performanceSettings: .compatibilityLocalModel,
        activeProvider: ProviderID("ollama"),
        contextEnforcementRoute: .init(
            provider: ProviderID("ollama"),
            model: ModelID("llama-tools:latest")
        )
    )
    #expect(compatibility["LOCAL_HARNESS_PERFORMANCE_PROFILE"] == "compatibility")
    #expect(compatibility["LOCAL_HARNESS_CONTEXT_WINDOW_TOKENS"] == "8192")
    #expect(compatibility["LOCAL_HARNESS_MAX_OUTPUT_TOKENS"] == "2048")
    #expect(compatibility["LOCAL_HARNESS_KEEP_ALIVE_SECONDS"] == "120")
    #expect(compatibility["LOCAL_HARNESS_CONTEXT_ENFORCEMENT"] == #"{"contextWindowTokens":8192,"model":"llama-tools:latest","provider":"ollama"}"#)
}

@Test func sandboxPolicyAllowsValidatedSkillResourcesReadOnlyAndKeepsThemOutsideWorkspace() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let workspace = root.appendingPathComponent("workspace", isDirectory: true)
    let skills = root.appendingPathComponent("skills", isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: skills, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: skills.path)
    defer { try? FileManager.default.removeItem(at: root) }

    let invocation = try LocalHarnessSandboxInvocation(
        arguments: [
            "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
            "--tmpfs", "/tmp", "--bind", workspace.path, workspace.path,
            "--", "/usr/bin/true"
        ],
        strictLocal: true,
        approvedWorkspaceRoots: [workspace],
        approvedReadOnlyRoots: [skills],
        currentDirectory: workspace
    )
    let canonicalSkills = skills.resolvingSymlinksInPath().standardizedFileURL
    #expect(invocation.approvedReadOnlyRoots == [canonicalSkills])
    #expect(invocation.profile.contains("(subpath \"\(canonicalSkills.path)\")"))
    #expect(invocation.profile.contains(#"LocalHarness(RuntimeLease|SandboxRunner)"#))
    #expect(invocation.profile.contains(#"/Fulmar\.app/Contents/MacOS/LocalHarness"#))
    #expect(!invocation.profile.contains(#"/Local Harness\.app/Contents/MacOS/LocalHarness"#))
    let writeAllows = invocation.profile.split(separator: "\n")
        .filter { $0.contains("(allow file-write*") }
        .joined(separator: "\n")
    #expect(!writeAllows.contains(canonicalSkills.path))
    let writeDenials = invocation.profile.split(separator: "\n")
        .filter { $0.contains("(deny file-write*") }
        .joined(separator: "\n")
    #expect(writeDenials.contains("(subpath \"\(canonicalSkills.path)\")"))
}

@Test func sandboxPolicyRejectsLinkedInsecureOrWorkspaceOverlappingReadOnlyRoots() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let workspace = root.appendingPathComponent("workspace", isDirectory: true)
    let insecure = root.appendingPathComponent("insecure", isDirectory: true)
    let privateRoot = root.appendingPathComponent("private", isDirectory: true)
    let linked = root.appendingPathComponent("linked", isDirectory: true)
    let nested = workspace.appendingPathComponent("nested", isDirectory: true)
    for directory in [workspace, insecure, privateRoot, nested] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: insecure.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: privateRoot.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: nested.path)
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: privateRoot)
    defer { try? FileManager.default.removeItem(at: root) }
    let arguments = [
        "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
        "--", "/usr/bin/true"
    ]

    for rejected in [insecure, linked, nested] {
        #expect(throws: LocalHarnessSandboxError.self) {
            _ = try LocalHarnessSandboxInvocation(
                arguments: arguments,
                strictLocal: true,
                approvedWorkspaceRoots: [workspace],
                approvedReadOnlyRoots: [rejected],
                currentDirectory: workspace
            )
        }
    }

    let protectedHome = try makeSecureNonUsersSandboxHome()
    let linkedHome = protectedHome.deletingLastPathComponent().appendingPathComponent(
        "fulmar-sandbox-linked-home-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createSymbolicLink(
        at: linkedHome,
        withDestinationURL: protectedHome
    )
    defer {
        try? FileManager.default.removeItem(at: linkedHome)
        try? FileManager.default.removeItem(at: protectedHome)
    }
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: arguments,
            strictLocal: true,
            approvedWorkspaceRoots: [workspace],
            protectedUserHome: linkedHome,
            currentDirectory: workspace
        )
    }
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o770],
        ofItemAtPath: protectedHome.path
    )
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: arguments,
            strictLocal: true,
            approvedWorkspaceRoots: [workspace],
            protectedUserHome: protectedHome,
            currentDirectory: workspace
        )
    }
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: protectedHome.path
    )
    try addSandboxReadACL(to: protectedHome)
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: arguments,
            strictLocal: true,
            approvedWorkspaceRoots: [workspace],
            protectedUserHome: protectedHome,
            currentDirectory: workspace
        )
    }
}

@Test func sandboxPolicyAcceptsDSHWorkspaceWriteGrammar() throws {
    let workspace = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: workspace) }
    let protectedHome = try makeSecureNonUsersSandboxHome()
    defer { try? FileManager.default.removeItem(at: protectedHome) }
    #expect(!protectedHome.path.hasPrefix("/Users/"))
    let invocation = try LocalHarnessSandboxInvocation(arguments: [
        "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
        "--tmpfs", "/tmp", "--bind", workspace.path, workspace.path,
        "--", "/usr/bin/touch", workspace.appendingPathComponent("created").path
    ], strictLocal: true, approvedWorkspaceRoots: [workspace],
       protectedUserHome: protectedHome, currentDirectory: workspace)
    #expect(invocation.mode == .workspaceWrite(workspace.resolvingSymlinksInPath().standardizedFileURL))
    #expect(invocation.command.first == "/usr/bin/touch")
    #expect(invocation.profile.contains("(deny file-write*)"))
    #expect(invocation.profile.contains(workspace.resolvingSymlinksInPath().path))
    #expect(invocation.profile.contains("deny network-outbound"))
    #expect(invocation.profile.contains("(deny file-read*)"))
    #expect(invocation.profile.contains("Library/Keychains"))
    #expect(invocation.profile.contains(
        "(subpath \"\(protectedHome.path)/Library/Keychains\")"
    ))
    #expect(invocation.profile.contains(
        "(subpath \"\(protectedHome.path)/.ssh\")"
    ))
    #expect(invocation.profile.contains(
        "(literal \"\(protectedHome.path)/.netrc\")"
    ))
    #expect(invocation.profile.contains("(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid))"))
    if FileManager.default.fileExists(atPath: "/private/var/select/sh") {
        #expect(invocation.profile.contains("(subpath \"/private/var/select\")"))
        #expect(invocation.profile.contains("(literal \"/private/var/select/sh\")"))
    }
}

@Test func sandboxPolicyAcceptsReadOnlyAndRejectsAlteredGrammar() throws {
    let base = ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent"]
    let workspace = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    let readOnly = try LocalHarnessSandboxInvocation(
        arguments: base + ["--", "/usr/bin/true"],
        strictLocal: false,
        approvedWorkspaceRoots: [workspace],
        currentDirectory: workspace
    )
    #expect(readOnly.mode == .readOnly)
    #expect(readOnly.profile.contains("deny network-outbound"))
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(arguments: ["--ro-bind", "/tmp", "/"] + base.dropFirst(3) + ["--", "/usr/bin/true"], strictLocal: true)
    }
}

@Test func supervisorChildPolicyConfinesFilesAndStrictLocalResources() throws {
    let workspace = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: workspace) }
    let invocation = try LocalHarnessSandboxInvocation(
        arguments: ["--supervisor-child", "--", "/usr/bin/curl", "https://example.com"],
        strictLocal: true,
        approvedWorkspaceRoots: [workspace],
        currentDirectory: workspace
    )
    #expect(invocation.mode == .supervisorChild)
    #expect(invocation.command.first == "/usr/bin/curl")
    #expect(invocation.profile.contains("deny file-write*)"))
    #expect(invocation.profile.contains("deny file-read*)"))
    #expect(invocation.profile.contains(workspace.resolvingSymlinksInPath().path))
    #expect(invocation.profile.contains("deny network-outbound"))
    #expect(invocation.profile.contains("git-credentials"))
    #expect(invocation.profile.contains("com.apple.SecurityServer"))
    #expect(invocation.profile.contains("deny appleevent-send"))
    #expect(invocation.profile.contains("LocalHarness(Credential|Update|Scheduler)Helper"))
    #expect(invocation.profile.contains("(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid))"))
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: ["--supervisor-child", "--"],
            strictLocal: true,
            approvedWorkspaceRoots: [workspace],
            currentDirectory: workspace
        )
    }
}

@Test func sandboxPolicyRejectsWorkspaceAndWorkingDirectoryOutsideApprovedRoots() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let approved = root.appendingPathComponent("approved", isDirectory: true)
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: approved, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let base = ["--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent"]

    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: base + ["--tmpfs", "/tmp", "--bind", outside.path, outside.path, "--", "/usr/bin/true"],
            strictLocal: true,
            approvedWorkspaceRoots: [approved],
            currentDirectory: outside
        )
    }
    #expect(throws: LocalHarnessSandboxError.self) {
        _ = try LocalHarnessSandboxInvocation(
            arguments: ["--supervisor-child", "--", "/usr/bin/true"],
            strictLocal: true,
            approvedWorkspaceRoots: [approved],
            currentDirectory: outside
        )
    }
}

@Test func workspacePolicyDeniesPreexistingHardLinkedFileAliases() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let workspace = root.appendingPathComponent("workspace", isDirectory: true)
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let source = outside.appendingPathComponent("source.txt")
    let alias = workspace.appendingPathComponent("alias.txt")
    try Data("protected".utf8).write(to: source)
    try FileManager.default.linkItem(at: source, to: alias)

    let invocation = try LocalHarnessSandboxInvocation(arguments: [
        "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc", "--die-with-parent",
        "--tmpfs", "/tmp", "--bind", workspace.path, workspace.path,
        "--", "/usr/bin/touch", alias.path
    ], strictLocal: true, approvedWorkspaceRoots: [workspace], currentDirectory: workspace)
    #expect(invocation.profile.contains("(deny file-write* (literal \"\(alias.path)\"))"))
}

@Test func endpointBuildsAuthenticatedPrivateRequests() {
    let endpoint = HarnessEndpoint(
        baseURL: URL(string: "http://127.0.0.1:49152/")!,
        token: "secret-token",
        nonce: "nonce",
        processIdentifier: 123
    )
    let request = endpoint.authenticatedRequest(to: endpoint.healthURL)
    #expect(request.value(forHTTPHeaderField: "X-Local-Harness-Token") == "secret-token")
    #expect(request.url?.path == "/_local_harness/health")
}

@Test func onlyExpectedLoopbackOriginIsEmbedded() {
    let policy = NavigationSecurityPolicy(port: 3080)
    #expect(policy.permitsEmbeddedNavigation(to: URL(string: "http://127.0.0.1:3080/session/1")!))
    #expect(policy.permitsEmbeddedNavigation(to: URL(string: "http://localhost:3080/")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "https://127.0.0.1:3080/")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "http://127.0.0.1:11434/")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "http://example.com:3080/")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "file:///etc/passwd")!))
}

@Test func internalDocumentSchemesRemainAvailable() {
    let policy = NavigationSecurityPolicy(port: 3080)
    #expect(policy.permitsEmbeddedNavigation(to: URL(string: "about:blank")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "about:srcdoc")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "data:text/plain,hello")!))
    #expect(policy.permitsEmbeddedNavigation(to: URL(string: "blob:http://127.0.0.1:3080/value")!))
    #expect(!policy.permitsEmbeddedNavigation(to: URL(string: "blob:http://example.com/value")!))
}

@Test func externalBrowserHandoffRequiresNormalizedCredentialFreeHTTPS() throws {
    let policy = NavigationSecurityPolicy(port: 3080)
    let normalized = try #require(policy.normalizedExternalHTTPSURL(
        URL(string: "HTTPS://Example.COM:443/a/../report?q=one#result")!
    ))
    #expect(normalized.absoluteString == "https://example.com/report?q=one#result")
    #expect(policy.isExternalWebURL(normalized))

    let customPort = try #require(policy.normalizedExternalHTTPSURL(
        URL(string: "https://EXAMPLE.com:8443/path")!
    ))
    #expect(customPort.absoluteString == "https://example.com:8443/path")

    #expect(policy.normalizedExternalHTTPSURL(URL(string: "http://example.com/report")!) == nil)
    #expect(policy.normalizedExternalHTTPSURL(URL(string: "https://user:secret@example.com/report")!) == nil)
    #expect(policy.normalizedExternalHTTPSURL(URL(string: "https:///missing-host")!) == nil)
    #expect(!policy.isExternalWebURL(URL(string: "http://example.com/report")!))
}

@Test func downloadFilenameIsSanitizedAndCollisionSafe() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let first = DownloadPath.uniqueURL(in: directory, suggestedFilename: "../report:final.pdf")
    #expect(first.deletingLastPathComponent().standardizedFileURL.path == directory.standardizedFileURL.path)
    #expect(first.lastPathComponent == "report-final.pdf")
    try Data().write(to: first)
    let second = DownloadPath.uniqueURL(in: directory, suggestedFilename: "../report:final.pdf")
    #expect(second.lastPathComponent == "report-final 2.pdf")
}

@Test func emptyDownloadNameGetsSafeDefault() {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    #expect(DownloadPath.uniqueURL(in: directory, suggestedFilename: "  ").lastPathComponent == "Download")
}

@Test func serviceLogsRotateAndRemainReadable() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ServiceLogStore(directory: directory, maxBytes: 40)
    store.append(Data(String(repeating: "a", count: 60).utf8), label: "test")
    store.append(Data("new-entry".utf8), label: "test")
    #expect(FileManager.default.fileExists(atPath: store.previousLogURL.path))
    #expect(store.recentLogs().contains("new-entry"))
}

@Test func serviceLogsRedactCredentialsAndControlCharacters() {
    let source = Data("Authorization: Bearer top-secret\nAPI_KEY=another-secret\nhttps://user:pass@example.com\u{001b}[31m".utf8)
    let result = String(decoding: ServiceLogStore.sanitized(source), as: UTF8.self)
    #expect(!result.contains("top-secret"))
    #expect(!result.contains("another-secret"))
    #expect(!result.contains(":pass@"))
    #expect(!result.contains("\u{001b}"))
    #expect(result.contains("<redacted>"))
}

@Test func serviceLogsStayBoundedWhenRotationDestinationIsBroken() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ServiceLogStore(directory: directory, maxBytes: 128, maximumChunkBytes: 64)
    store.append(Data(String(repeating: "a", count: 96).utf8), label: "first")
    try FileManager.default.createDirectory(at: store.previousLogURL, withIntermediateDirectories: false)

    store.append(Data("LATEST-ROTATION-ENTRY".utf8), label: "second")

    let size = try #require(store.logURL.resourceValues(forKeys: [.fileSizeKey]).fileSize)
    #expect(size <= 128)
    #expect(store.recentLogs().contains("LATEST-ROTATION-ENTRY"))
    #expect(try store.previousLogURL.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true)
}

@Test func serviceLogsBoundSparseReadsChunksAndSymlinkReplacement() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let directory = root.appendingPathComponent("logs", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    defer { try? FileManager.default.removeItem(at: root) }
    let store = ServiceLogStore(directory: directory, maxBytes: 1_024, maximumChunkBytes: 32)
    FileManager.default.createFile(atPath: store.logURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let sparse = try FileHandle(forWritingTo: store.logURL)
    try sparse.truncate(atOffset: 64 * 1_024 * 1_024)
    try sparse.close()
    #expect(store.recentLogs(maxCharacters: 40) == "No service log entries yet.")

    store.append(Data(String(repeating: "z", count: 10_000).utf8), label: "oversized")
    let rewrittenSize = try #require(store.logURL.resourceValues(forKeys: [.fileSizeKey]).fileSize)
    #expect(rewrittenSize == 64 * 1_024 * 1_024)
    #expect(store.recentLogs() == "No service log entries yet.")

    let outside = root.appendingPathComponent("outside.log")
    try Data("outside-must-remain".utf8).write(to: outside)
    try FileManager.default.removeItem(at: store.logURL)
    try FileManager.default.createSymbolicLink(at: store.logURL, withDestinationURL: outside)
    store.append(Data("safe-replacement".utf8), label: "symlink")
    #expect(try String(contentsOf: outside, encoding: .utf8) == "outside-must-remain")
    #expect(store.recentLogs() == "No service log entries yet.")
    var linkedMetadata = stat()
    #expect(Darwin.lstat(store.logURL.path, &linkedMetadata) == 0)
    #expect(linkedMetadata.st_mode & S_IFMT == S_IFLNK)
}

@Test func backupsExcludeSecretsAndRestoreState() throws {
    let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-backup-secret-filter")
    defer { try? FileManager.default.removeItem(at: temporary) }
    let source = temporary.appendingPathComponent("state")
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let root = temporary.appendingPathComponent("backups")
    try FileManager.default.createDirectory(at: source.appendingPathComponent("profiles"), withIntermediateDirectories: true)
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    try Data("before".utf8).write(to: source.appendingPathComponent("session.json"))
    try Data("secret".utf8).write(to: source.appendingPathComponent(".credentials.yaml"))
    try Data("secret".utf8).write(to: source.appendingPathComponent("profiles/.env"))
    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: root,
        authenticationKey: Data(repeating: 0x21, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    let backup = try manager.create(label: "test", sourceVersion: "old")
    let snapshot = URL(fileURLWithPath: backup.path)
    #expect(FileManager.default.fileExists(atPath: snapshot.appendingPathComponent("session.json").path))
    #expect(!FileManager.default.fileExists(atPath: snapshot.appendingPathComponent(".credentials.yaml").path))
    #expect(!FileManager.default.fileExists(atPath: snapshot.appendingPathComponent("profiles/.env").path))

    try Data("after".utf8).write(to: source.appendingPathComponent("session.json"), options: .atomic)
    try manager.restore(backup)
    #expect(try String(contentsOf: source.appendingPathComponent("session.json"), encoding: .utf8) == "before")
}

@Test func runtimeMigrationRequiresRecoveryUntilReady() throws {
    let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-runtime-migration")
    defer { try? FileManager.default.removeItem(at: temporary) }
    let source = temporary.appendingPathComponent("state")
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let backups = temporary.appendingPathComponent("backups")
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(
        at: support,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    try Data("state".utf8).write(to: source.appendingPathComponent("session.json"))
    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x22, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    let coordinator = RuntimeMigrationCoordinator(
        applicationSupport: support,
        backupManager: manager,
        attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
    )

    guard case .backupCreated(let backup) = try coordinator.prepare(targetVersion: "1.2.3") else { Issue.record("Expected a safety backup"); return }
    guard case .recoveryNeeded(let recovery) = try coordinator.prepare(targetVersion: "1.2.3") else { Issue.record("Expected recovery state"); return }
    #expect(recovery.id == backup.id)
    try coordinator.markReady(version: "1.2.3")
    #expect(try coordinator.prepare(targetVersion: "1.2.3") == .current)
    let state = support.appendingPathComponent("Migration/runtime-state.json")
    let object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: state)) as? [String: Any]
    )
    #expect(Set(object.keys) == [
        "formatVersion", "providerHistoryPrivacyEpoch", "installedVersion",
        "pendingVersion", "pendingBackupID", "attemptStartedAt"
    ])
    #expect((object["formatVersion"] as? NSNumber)?.intValue == 1)
    #expect((object["providerHistoryPrivacyEpoch"] as? NSNumber)?.intValue
        == ProviderHistoryPrivacyEpoch.current)
}

@Test func runtimeMigrationPrePreparedCrashIsPreservedWholeBeforeRetry() throws {
    for phase in [
        RuntimeMigrationPublicationPhase.stagingDirectorySynced,
        .stagingStateSynced
    ] {
        let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-migration-prepared-gap")
        defer { try? FileManager.default.removeItem(at: temporary) }
        let source = temporary.appendingPathComponent("state", isDirectory: true)
        let support = temporary.appendingPathComponent("support", isDirectory: true)
        let backups = temporary.appendingPathComponent("backups", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try writeCurrentProviderHistoryPrivacyReceipt(at: source)
        try Data("state".utf8).write(to: source.appendingPathComponent("session.json"))
        let manager = StateBackupManager(
            applicationSupport: support,
            sourceState: source,
            backupRoot: backups,
            authenticationKey: Data(repeating: 0x35, count: 32),
            allowUnattestedHarnessHomeForTesting: true
        )
        let keyStore = LocalHarnessTestDeviceAttestationKeyStore()
        let migration = RuntimeMigrationCoordinator(
            applicationSupport: support,
            backupManager: manager,
            attestationKeyStore: keyStore,
            publicationInterruption: { $0 == phase }
        )
        #expect(throws: RuntimeMigrationPublicationTestInterruption.self) {
            _ = try migration.prepare(targetVersion: "1.2.3")
        }
        let staging = support.appendingPathComponent(
            ProviderHistoryDeviceAttestation.migrationStagingLeafName,
            isDirectory: true
        )
        #expect(FileManager.default.fileExists(atPath: staging.path))
        #expect(!FileManager.default.fileExists(
            atPath: support.appendingPathComponent("Migration").path
        ))

        let auxiliary = ProviderHistoryAuxiliaryStateCoordinator(
            applicationSupport: support,
            attestationKeyStore: keyStore
        )
        guard case .initial(let request) = try auxiliary.preflight() else {
            Issue.record("Expected pre-prepared staging recovery for \(phase)")
            continue
        }
        let receipt = try auxiliary.preserveAfterExplicitAcknowledgement(request)
        #expect(receipt.preservedMigrationStaging != nil)
        #expect(!FileManager.default.fileExists(atPath: staging.path))
    }
}

@Test func pendingMigrationBackupCannotBeDeletedEvictedOrReplaced() throws {
    let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-migration-pinned")
    defer { try? FileManager.default.removeItem(at: temporary) }
    let source = temporary.appendingPathComponent("state", isDirectory: true)
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let backups = temporary.appendingPathComponent("backups", isDirectory: true)
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(
        at: support,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    try Data("state".utf8).write(to: source.appendingPathComponent("session.json"))
    var limits = StateBackupLimits.production
    limits.maximumBackupCount = 1
    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x53, count: 32),
        limits: limits,
        allowUnattestedHarnessHomeForTesting: true
    )
    let coordinator = RuntimeMigrationCoordinator(
        applicationSupport: support,
        backupManager: manager,
        attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
    )
    guard case .backupCreated(let pending) = try coordinator.prepare(targetVersion: "2.0") else {
        Issue.record("Expected a pending migration backup")
        return
    }

    #expect(manager.isMigrationBackupProtected(id: pending.id))
    #expect(throws: BackupError.self) { try manager.delete(pending) }
    #expect(throws: BackupError.self) {
        _ = try manager.create(label: "manual", sourceVersion: "2.0")
    }
    guard case .recoveryNeeded(let sameBackup) = try coordinator.prepare(targetVersion: "3.0") else {
        Issue.record("Any durable pending migration must win over a newer target")
        return
    }
    #expect(sameBackup.id == pending.id)
    #expect(try manager.validatedList() == [pending])

    try coordinator.markReady(version: "2.0")
    #expect(!manager.isMigrationBackupProtected(id: pending.id))
    try manager.delete(pending)
    #expect(try manager.validatedList().isEmpty)
}

@Test func missingPendingMigrationBackupFailsClosedWithoutCreatingAReplacement() throws {
    let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-migration-missing")
    defer { try? FileManager.default.removeItem(at: temporary) }
    let source = temporary.appendingPathComponent("state", isDirectory: true)
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let backups = temporary.appendingPathComponent("backups", isDirectory: true)
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(
        at: support,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    try Data("state".utf8).write(to: source.appendingPathComponent("session.json"))
    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x54, count: 32),
        allowUnattestedHarnessHomeForTesting: true
    )
    let coordinator = RuntimeMigrationCoordinator(
        applicationSupport: support,
        backupManager: manager,
        attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
    )
    guard case .backupCreated(let pending) = try coordinator.prepare(targetVersion: "2.0") else {
        Issue.record("Expected a pending migration backup")
        return
    }
    let container = URL(fileURLWithPath: pending.path).deletingLastPathComponent()
    try FileManager.default.removeItem(at: container)

    #expect(throws: BackupError.self) {
        _ = try coordinator.prepare(targetVersion: "3.0")
    }
    let remainingContainers = try FileManager.default.contentsOfDirectory(
        at: backups,
        includingPropertiesForKeys: [.isDirectoryKey],
        options: [.skipsHiddenFiles]
    ).filter { UUID(uuidString: $0.lastPathComponent) != nil }
    #expect(remainingContainers.isEmpty)
    #expect(manager.isMigrationBackupProtected(id: pending.id))
}

@Test func runtimeMigrationRejectsHostileStateWithoutCreatingABackup() throws {
    enum HostileState: Equatable {
        case corrupt
        case oversized
        case symbolicLink
        case permissive
    }

    for hostile in [HostileState.corrupt, .oversized, .symbolicLink, .permissive] {
        let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-migration-hostile")
        let source = temporary.appendingPathComponent("state", isDirectory: true)
        let support = temporary.appendingPathComponent("support", isDirectory: true)
        let migrationDirectory = support.appendingPathComponent("Migration", isDirectory: true)
        let state = migrationDirectory.appendingPathComponent("runtime-state.json")
        let outside = temporary.appendingPathComponent("outside-state.json")
        let backups = temporary.appendingPathComponent("backups", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
        try writeCurrentProviderHistoryPrivacyReceipt(at: source)
        try FileManager.default.createDirectory(at: migrationDirectory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: migrationDirectory.path)
        try Data("reviewed-state".utf8).write(to: source.appendingPathComponent("session.json"))

        let original: Data
        switch hostile {
        case .corrupt:
            original = Data("not-json".utf8)
            try original.write(to: state)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
        case .oversized:
            original = Data(repeating: 0x41, count: 64 * 1_024 + 1)
            try original.write(to: state)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
        case .symbolicLink:
            original = Data("{}".utf8)
            try original.write(to: outside)
            try FileManager.default.createSymbolicLink(at: state, withDestinationURL: outside)
        case .permissive:
            original = Data("{}".utf8)
            try original.write(to: state)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: state.path)
        }

        let manager = StateBackupManager(
            applicationSupport: support,
            sourceState: source,
            backupRoot: backups,
            authenticationKey: Data(repeating: 0x4D, count: 32),
            allowUnattestedHarnessHomeForTesting: true
        )
        let before = try manager.validatedList()
        let coordinator = RuntimeMigrationCoordinator(
            applicationSupport: support,
            backupManager: manager,
            attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
        )
        #expect(throws: RuntimeMigrationStateError.self) {
            _ = try coordinator.prepare(targetVersion: "1.2.3")
        }
        #expect(try manager.validatedList() == before)
        if hostile == .symbolicLink {
            #expect(try Data(contentsOf: outside) == original)
        } else {
            #expect(try Data(contentsOf: state) == original)
        }
        try? FileManager.default.removeItem(at: temporary)
    }
}

@Test func runtimeMigrationPreservesHistoricalStateWithoutLinkingItsBackupID() throws {
    let temporary = try makeSecureAttestationTestRoot(prefix: "fulmar-migration-privacy-epoch")
    let source = temporary.appendingPathComponent("state", isDirectory: true)
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let migrationDirectory = support.appendingPathComponent("Migration", isDirectory: true)
    let stateURL = migrationDirectory.appendingPathComponent("runtime-state.json")
    let backups = temporary.appendingPathComponent("backups", isDirectory: true)
    let historicalBackupID = UUID()
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try writeCurrentProviderHistoryPrivacyReceipt(at: source)
    try FileManager.default.createDirectory(at: migrationDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: migrationDirectory.path)
    let historicalState = try JSONSerialization.data(withJSONObject: [
        "installedVersion": "1.0",
        "pendingVersion": "2.0",
        "pendingBackupID": historicalBackupID.uuidString,
        "attemptStartedAt": 0.0
    ], options: [.sortedKeys])
    try historicalState.write(to: stateURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateURL.path)
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = StateBackupManager(
        applicationSupport: support,
        sourceState: source,
        backupRoot: backups,
        authenticationKey: Data(repeating: 0x71, count: 32)
    )
    #expect(try RuntimeMigrationCoordinator.privacyEpochPreflight(
        applicationSupport: support
    ) == .historical)
    let coordinator = RuntimeMigrationCoordinator(
        applicationSupport: support,
        backupManager: manager,
        attestationKeyStore: LocalHarnessTestDeviceAttestationKeyStore()
    )
    #expect(!manager.isMigrationBackupProtected(id: historicalBackupID))
    do {
        _ = try coordinator.prepare(targetVersion: "2.0")
        Issue.record("Expected historical runtime migration classification")
    } catch let error as RuntimeMigrationStateError {
        guard case .providerHistoryPrivacyMigrationRequired = error else {
            Issue.record("Unexpected runtime migration error: \(error)")
            return
        }
    }
    #expect(try Data(contentsOf: stateURL) == historicalState)
    #expect(!FileManager.default.fileExists(atPath: backups.path))
}

@Test func runtimeMigrationDetectionOnlyPreflightDoesNotCreateStorage() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("migration-detection-only-\(UUID().uuidString)", isDirectory: true)
    let support = root.appendingPathComponent("support", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(try RuntimeMigrationCoordinator.privacyEpochPreflight(
        applicationSupport: support
    ) == .absent)
    #expect(!FileManager.default.fileExists(atPath: root.path))
    #expect(!FileManager.default.fileExists(
        atPath: support.appendingPathComponent("Migration").path
    ))
}

@Test func futureRuntimeMigrationEpochIsHistoricalAndUnchanged() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("migration-future-epoch-\(UUID().uuidString)", isDirectory: true)
    let support = root.appendingPathComponent("support", isDirectory: true)
    let migration = support.appendingPathComponent("Migration", isDirectory: true)
    let state = migration.appendingPathComponent("runtime-state.json")
    try FileManager.default.createDirectory(at: migration, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: migration.path)
    let bytes = try JSONSerialization.data(withJSONObject: [
        "formatVersion": 2,
        "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current + 1,
        "installedVersion": NSNull(),
        "pendingVersion": NSNull(),
        "pendingBackupID": NSNull(),
        "attemptStartedAt": NSNull()
    ], options: [.sortedKeys])
    try bytes.write(to: state)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: state.path)
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(try RuntimeMigrationCoordinator.privacyEpochPreflight(
        applicationSupport: support
    ) == .historical)
    #expect(try Data(contentsOf: state) == bytes)
}

private struct PluginTrustFixture {
    let root: URL
    let support: URL
    let profiles: URL
    let web: URL
    let plugin: URL
}

private func makePluginTrustFixture(
    name: String = "example-plugin",
    includeImplementation: Bool = true
) throws -> PluginTrustFixture {
    let root = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarPluginTrust")
    let support = root.appendingPathComponent("support", isDirectory: true)
    let profiles = root.appendingPathComponent("profiles")
    let web = profiles.appendingPathComponent("web")
    let plugin = web.appendingPathComponent("node_modules").appendingPathComponent(name)
    try FileManager.default.createDirectory(at: plugin, withIntermediateDirectories: true)
    let package = ["dependencies": [name: "1.0.0"]]
    try JSONSerialization.data(withJSONObject: package).write(to: web.appendingPathComponent("package.json"))
    if includeImplementation {
        try Data("export default 1".utf8).write(to: plugin.appendingPathComponent("index.js"))
    }
    return PluginTrustFixture(root: root, support: support, profiles: profiles, web: web, plugin: plugin)
}

private func openDescriptorCount(beneath root: URL) -> Int {
    let prefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
    let requiredBytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nil, 0)
    guard requiredBytes > 0 else { return -1 }
    let stride = MemoryLayout<proc_fdinfo>.stride
    guard let plan = OwnedLoopbackListenerVerifier.descriptorBufferPlan(
        requiredBytes: requiredBytes,
        stride: stride
    ) else { return -1 }
    var descriptors = [proc_fdinfo](
        repeating: proc_fdinfo(),
        count: plan.capacity
    )
    let returnedBytes = proc_pidinfo(
        getpid(),
        PROC_PIDLISTFDS,
        0,
        &descriptors,
        plan.byteCount
    )
    guard returnedBytes > 0,
          returnedBytes <= plan.byteCount,
          Int(returnedBytes).isMultiple(of: stride) else { return -1 }
    var count = 0
    for descriptor in descriptors.prefix(Int(returnedBytes) / stride)
    where descriptor.proc_fdtype == PROX_FDTYPE_VNODE {
        var information = vnode_fdinfowithpath()
        let size = proc_pidfdinfo(
            getpid(),
            descriptor.proc_fd,
            PROC_PIDFDVNODEPATHINFO,
            &information,
            Int32(MemoryLayout<vnode_fdinfowithpath>.stride)
        )
        guard size == MemoryLayout<vnode_fdinfowithpath>.stride else { continue }
        let path = withUnsafePointer(to: &information.pvip.vip_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
        if path == root.path || path.hasPrefix(prefix) { count += 1 }
    }
    return count
}

@Test func communityPluginApprovalPinsInstalledCode() throws {
    let temporary = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarCommunityPlugin")
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let profiles = temporary.appendingPathComponent("profiles")
    let web = profiles.appendingPathComponent("web")
    let plugin = web.appendingPathComponent("node_modules/example-plugin")
    try FileManager.default.createDirectory(at: plugin, withIntermediateDirectories: true)
    let package = ["dependencies": ["example-plugin": "1.0.0"]]
    try JSONSerialization.data(withJSONObject: package).write(to: web.appendingPathComponent("package.json"))
    try Data("export default 1".utf8).write(to: plugin.appendingPathComponent("index.js"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let store = PluginTrustStore(applicationSupport: support, profileRoot: profiles)
    let blocked = try #require(store.audit().first)
    #expect(blocked.status == .blocked)
    try store.approve(blocked)
    #expect(store.audit().first?.status == .approved)
    try Data("export default 2".utf8).write(to: plugin.appendingPathComponent("index.js"), options: .atomic)
    #expect(store.audit().first?.status == .blocked)
}

@Test func pluginTrustRejectsAnEmptyPluginTreeAsNonApprovable() throws {
    let fixture = try makePluginTrustFixture(includeImplementation: false)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)

    let finding = try #require(store.audit().first)
    #expect(finding.status == .blocked)
    #expect(finding.fingerprint == PluginTrustStore.blockedFingerprint)
    try store.approve(finding)
    #expect(store.audit().first?.status == .blocked)
    #expect(store.audit().first?.fingerprint == PluginTrustStore.blockedFingerprint)
}

@Test func pluginTrustCapsTreeDepthEntryCountAndFileBytes() throws {
    let fixture = try makePluginTrustFixture(includeImplementation: false)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let deep = fixture.plugin.appendingPathComponent("a/b/c", isDirectory: true)
    try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
    try Data("x".utf8).write(to: deep.appendingPathComponent("index.js"))
    var finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumDepth: 2)
    ).audit().first)
    #expect(finding.status == .blocked)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)

    try FileManager.default.removeItem(at: fixture.plugin)
    try FileManager.default.createDirectory(at: fixture.plugin, withIntermediateDirectories: true)
    try Data(repeating: 0x41, count: 9).write(to: fixture.plugin.appendingPathComponent("large.js"))
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumFileBytes: 8, maximumAggregateBytes: 16)
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)

    try FileManager.default.removeItem(at: fixture.plugin)
    try FileManager.default.createDirectory(at: fixture.plugin, withIntermediateDirectories: true)
    try Data(repeating: 0x42, count: 6).write(to: fixture.plugin.appendingPathComponent("one.js"))
    try Data(repeating: 0x43, count: 6).write(to: fixture.plugin.appendingPathComponent("two.js"))
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumFileBytes: 8, maximumAggregateBytes: 10)
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)

    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumEntries: 1)
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)
}

@Test func pluginTrustCapsPackageAndProfileDeclarationBytesAndCount() throws {
    let fixture = try makePluginTrustFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let packageURL = fixture.web.appendingPathComponent("package.json")
    try Data(repeating: 0x20, count: 256).write(to: packageURL)
    var finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumDeclarationFileBytes: 128)
    ).audit().first)
    #expect(finding.status == .blocked)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)

    let package = ["dependencies": ["example-plugin": "1.0.0"]]
    try JSONSerialization.data(withJSONObject: package).write(to: packageURL)
    try Data(repeating: 0x20, count: 256).write(to: fixture.web.appendingPathComponent("cordis.patch.yml"))
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumDeclarationFileBytes: 128)
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)

    try FileManager.default.removeItem(at: fixture.web.appendingPathComponent("cordis.patch.yml"))
    let dependencies = Dictionary(uniqueKeysWithValues: (0..<3).map { ("plugin-\($0)", "1") })
    try JSONSerialization.data(withJSONObject: ["dependencies": dependencies]).write(to: packageURL)
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(maximumDeclarations: 2)
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.oversizeFingerprint)
}

@Test func pluginTrustNeverFollowsSymlinksOrOpensSpecialObjects() throws {
    let fixture = try makePluginTrustFixture(includeImplementation: false)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let outside = fixture.root.appendingPathComponent("outside-secret")
    try Data("must-not-be-read".utf8).write(to: outside)
    let member = fixture.plugin.appendingPathComponent("index.js")
    try FileManager.default.createSymbolicLink(at: member, withDestinationURL: outside)
    var finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles
    ).audit().first)
    #expect(finding.status == .blocked)
    #expect(finding.fingerprint == PluginTrustStore.blockedFingerprint)

    try FileManager.default.removeItem(at: member)
    #expect(Darwin.mkfifo(member.path, 0o600) == 0)
    let started = Date()
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles
    ).audit().first)
    #expect(Date().timeIntervalSince(started) < 1)
    #expect(finding.fingerprint == PluginTrustStore.blockedFingerprint)

    try FileManager.default.removeItem(at: member)
    let declaration = fixture.web.appendingPathComponent("package.json")
    try FileManager.default.removeItem(at: declaration)
    try FileManager.default.createSymbolicLink(at: declaration, withDestinationURL: outside)
    finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles
    ).audit().first)
    #expect(finding.fingerprint == PluginTrustStore.blockedFingerprint)
}

@Test func pluginTrustUsesOneMonotonicAuditDeadline() throws {
    let fixture = try makePluginTrustFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let started = DispatchTime.now().uptimeNanoseconds
    let finding = try #require(PluginTrustStore(
        applicationSupport: fixture.support,
        profileRoot: fixture.profiles,
        limits: .init(scanDuration: 0)
    ).audit().first)
    let elapsed = DispatchTime.now().uptimeNanoseconds - started
    #expect(finding.status == .blocked)
    #expect(finding.fingerprint == PluginTrustStore.deadlineFingerprint)
    #expect(elapsed < 1_000_000_000)
}

@Test func pluginTrustRepeatedAuditsDoNotLeakPackageDescriptors() throws {
    let fixture = try makePluginTrustFixture(name: "@deepseek-ai/dsh-base")
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
    let baseline = openDescriptorCount(beneath: fixture.root)
    for _ in 0..<200 {
        let finding = try #require(store.audit().first)
        #expect(finding.status == .blocked)
    }
    #expect(openDescriptorCount(beneath: fixture.root) == baseline)
}

@Test func pluginTrustLoadsOnlyBoundedPrivateValidatedApprovalState() throws {
    let fixture = try makePluginTrustFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let initial = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
    let blocked = try #require(initial.audit().first)
    try initial.approve(blocked)
    #expect(PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        .audit().first?.status == .approved)

    let storeURL = fixture.support.appendingPathComponent("Security/plugin-trust.json")
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: storeURL.path)
    #expect(PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        .audit().first?.status == .blocked)

    try Data(repeating: 0x41, count: 256 * 1_024 + 1).write(to: storeURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storeURL.path)
    #expect(PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        .audit().first?.status == .blocked)

    let invalid = [
        "example-plugin": [
            "name": "different-plugin",
            "fingerprint": String(repeating: "a", count: 64),
            "approvedAt": 0
        ] as [String: Any]
    ]
    try JSONSerialization.data(withJSONObject: invalid).write(to: storeURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: storeURL.path)
    #expect(PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        .audit().first?.status == .blocked)

    let outside = fixture.root.appendingPathComponent("outside-approvals.json")
    try FileManager.default.copyItem(at: storeURL, to: outside)
    try FileManager.default.removeItem(at: storeURL)
    try FileManager.default.createSymbolicLink(at: storeURL, withDestinationURL: outside)
    #expect(PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        .audit().first?.status == .blocked)
}

@Test func pluginTrustApprovalPublicationRejectsLinkedDestinationAndRollsBackMemory() throws {
    let fixture = try makePluginTrustFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
    let blocked = try #require(store.audit().first)
    let security = fixture.support.appendingPathComponent("Security", isDirectory: true)
    let destination = security.appendingPathComponent("plugin-trust.json")
    let outside = fixture.root.appendingPathComponent("outside-approval.json")
    let sentinel = Data("must-not-be-replaced".utf8)
    try sentinel.write(to: outside)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
    try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: outside)

    #expect(throws: (any Error).self) { try store.approve(blocked) }
    #expect(try Data(contentsOf: outside) == sentinel)
    #expect(store.audit().first?.status == .blocked)
    #expect(try FileManager.default.contentsOfDirectory(atPath: security.path)
        .filter { $0.hasPrefix(".plugin-trust.") }.isEmpty)
}

@Test func pluginTrustApprovalPublicationRejectsDirectoryReplacementAndHardLinks() throws {
    do {
        let fixture = try makePluginTrustFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        let blocked = try #require(store.audit().first)
        let security = fixture.support.appendingPathComponent("Security", isDirectory: true)
        let retained = fixture.support.appendingPathComponent("Security-retained", isDirectory: true)
        let outside = fixture.root.appendingPathComponent("replacement", isDirectory: true)
        try FileManager.default.moveItem(at: security, to: retained)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: outside.path)
        try FileManager.default.createSymbolicLink(at: security, withDestinationURL: outside)

        #expect(throws: (any Error).self) { try store.approve(blocked) }
        #expect(store.audit().first?.status == .blocked)
        #expect(!FileManager.default.fileExists(
            atPath: outside.appendingPathComponent("plugin-trust.json").path
        ))
    }

    do {
        let fixture = try makePluginTrustFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = PluginTrustStore(applicationSupport: fixture.support, profileRoot: fixture.profiles)
        let blocked = try #require(store.audit().first)
        let security = fixture.support.appendingPathComponent("Security", isDirectory: true)
        let destination = security.appendingPathComponent("plugin-trust.json")
        let outside = fixture.root.appendingPathComponent("hard-linked-approval.json")
        let sentinel = Data("hard-link-sentinel".utf8)
        try sentinel.write(to: outside)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outside.path)
        #expect(Darwin.link(outside.path, destination.path) == 0)

        #expect(throws: (any Error).self) { try store.approve(blocked) }
        #expect(try Data(contentsOf: outside) == sentinel)
        #expect(store.audit().first?.status == .blocked)
    }
}

@Test func builtInPluginNameDoesNotTrustAProfileOverride() throws {
    let temporary = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarPluginOverride")
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let profiles = temporary.appendingPathComponent("profiles")
    let web = profiles.appendingPathComponent("web")
    let plugin = web.appendingPathComponent("node_modules/@deepseek-ai/unreviewed")
    try FileManager.default.createDirectory(at: plugin, withIntermediateDirectories: true)
    let package = ["dependencies": ["@deepseek-ai/unreviewed": "1.0.0"]]
    try JSONSerialization.data(withJSONObject: package).write(to: web.appendingPathComponent("package.json"))
    try Data("export default 'override'".utf8).write(to: plugin.appendingPathComponent("index.js"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let store = PluginTrustStore(applicationSupport: support, profileRoot: profiles)
    let finding = try #require(store.audit().first)
    #expect(finding.source == "package.json")
    #expect(finding.name == "@deepseek-ai/unreviewed")
    #expect(finding.status == .blocked)
}

@Test func secretFilenameClassifierCoversCredentialsAndPrivateKeys() {
    #expect(StateBackupManager.isSecretBearingFile(".credentials.yaml"))
    #expect(StateBackupManager.isSecretBearingFile(".env.production"))
    #expect(StateBackupManager.isSecretBearingFile("client-private-key.txt"))
    #expect(StateBackupManager.isSecretBearingFile("identity.pem"))
    #expect(StateBackupManager.isSecretBearingFile("certificate.p12"))
    #expect(!StateBackupManager.isSecretBearingFile("session.json"))
    #expect(!StateBackupManager.isSecretBearingFile("notes.md"))
}

@Test func presetPolicyAllowsOnlyReviewedShippedPresets() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    for identifier in ["standard"] {
        let directory = root.appendingPathComponent(identifier, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("""
        - id: tool-fs
          name: '@deepseek-ai/dsh-tool-fs'
        - id: skill-filesystem
          name: '@deepseek-ai/dsh-skill-filesystem'
          config:
            includeDefaultRoots: false
            bundledSkillDir: !!js "process.getBuiltinModule('node:path').join(process.env.DSH_HOME, 'skills', 'Active')"
            watchFollowSymlinks: false
        - id: tool-web
          name: '@deepseek-ai/dsh-tool-web'
          config:
            search: false
            fetch: true
            fetchTimeoutMs: 30000
            fetchMaxOutputChars: 200000

        """.utf8)
            .write(to: directory.appendingPathComponent("agent.cordis.yml"))
        try Data("name: Standard\n".utf8).write(to: directory.appendingPathComponent("preset.yml"))
    }
    let composition = try Data(contentsOf: root.appendingPathComponent("standard/agent.cordis.yml"))
    let digest = SHA256.hash(data: composition).map { String(format: "%02x", $0) }.joined()
    let manifest = "{\"version\":1,\"allowedPresetIDs\":[\"standard\"],\"removedRowIDs\":[\"tool-ralph\",\"tool-workflow\",\"workflow-worker-thread\"],\"compositionSHA256\":\"\(digest)\"}"
    try Data(manifest.utf8).write(to: root.appendingPathComponent("local-harness-policy.json"))
    #expect(PresetSecurityPolicy.validatePresetRoot(root))

    let minimal = root.appendingPathComponent("minimal", isDirectory: true)
    try FileManager.default.createDirectory(at: minimal, withIntermediateDirectories: true)
    try Data("- id: fs\n  name: '@deepseek-ai/dsh-fs-local'\n".utf8)
        .write(to: minimal.appendingPathComponent("agent.cordis.yml"))
    #expect(!PresetSecurityPolicy.validatePresetRoot(root))
}

@Test func presetPolicyRejectsCredentialDependentSearchEvenWithMatchingDigest() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let standard = root.appendingPathComponent("standard", isDirectory: true)
    try FileManager.default.createDirectory(at: standard, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let composition = """
    - id: skill-filesystem
      config:
        includeDefaultRoots: false
        bundledSkillDir: !!js "process.getBuiltinModule('node:path').join(process.env.DSH_HOME, 'skills', 'Active')"
        watchFollowSymlinks: false
    - id: tool-web
      name: '@deepseek-ai/dsh-tool-web'
      config:
        search: true
        fetch: false
        fetchTimeoutMs: 30000
        fetchMaxOutputChars: 200000

    """
    let bytes = Data(composition.utf8)
    try bytes.write(to: standard.appendingPathComponent("agent.cordis.yml"))
    try Data("name: Unsafe\n".utf8).write(to: standard.appendingPathComponent("preset.yml"))
    let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    let manifest = "{\"version\":1,\"allowedPresetIDs\":[\"standard\"],\"removedRowIDs\":[\"tool-ralph\",\"tool-workflow\",\"workflow-worker-thread\"],\"compositionSHA256\":\"\(digest)\"}"
    try Data(manifest.utf8).write(to: root.appendingPathComponent("local-harness-policy.json"))
    #expect(!PresetSecurityPolicy.validatePresetRoot(root))
}

@Test func presetPolicyBoundsWideDirectoriesAndParsedFilesBeforeDecoding() throws {
    func validRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let standard = root.appendingPathComponent("standard", isDirectory: true)
        try FileManager.default.createDirectory(at: standard, withIntermediateDirectories: true)
        let composition = """
        - id: skill-filesystem
          config:
            includeDefaultRoots: false
            bundledSkillDir: !!js "process.getBuiltinModule('node:path').join(process.env.DSH_HOME, 'skills', 'Active')"
            watchFollowSymlinks: false
        - id: tool-web
          name: '@deepseek-ai/dsh-tool-web'
          config:
            search: false
            fetch: true
            fetchTimeoutMs: 30000
            fetchMaxOutputChars: 200000

        """
        let compositionData = Data(composition.utf8)
        try compositionData.write(to: standard.appendingPathComponent("agent.cordis.yml"))
        try Data("name: Standard\n".utf8).write(to: standard.appendingPathComponent("preset.yml"))
        let digest = SHA256.hash(data: compositionData).map { String(format: "%02x", $0) }.joined()
        let manifest = "{\"version\":1,\"allowedPresetIDs\":[\"standard\"],\"removedRowIDs\":[\"tool-ralph\",\"tool-workflow\",\"workflow-worker-thread\"],\"compositionSHA256\":\"\(digest)\"}"
        try Data(manifest.utf8).write(to: root.appendingPathComponent("local-harness-policy.json"))
        return root
    }

    do {
        let root = try validRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        for index in 0..<256 {
            try Data().write(to: root.appendingPathComponent("unexpected-\(index)"))
        }
        #expect(!PresetSecurityPolicy.validatePresetRoot(root))
    }

    do {
        let root = try validRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data(repeating: 0x20, count: PresetSecurityPolicy.maximumCompositionBytes + 1)
            .write(to: root.appendingPathComponent("standard/agent.cordis.yml"))
        #expect(!PresetSecurityPolicy.validatePresetRoot(root))
    }

    do {
        let root = try validRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data(repeating: 0x20, count: PresetSecurityPolicy.maximumManifestBytes + 1)
            .write(to: root.appendingPathComponent("local-harness-policy.json"))
        #expect(!PresetSecurityPolicy.validatePresetRoot(root))
    }


    do {
        let root = try validRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let composition = root.appendingPathComponent("standard/agent.cordis.yml")
        try FileManager.default.removeItem(at: composition)
        #expect(Darwin.mkfifo(composition.path, 0o600) == 0)
        #expect(!PresetSecurityPolicy.validatePresetRoot(root))
    }
}

@Test func presetPolicyRejectsSymlinkedOrHiddenPolicyMaterial() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let outside = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let standard = root.appendingPathComponent("standard", isDirectory: true)
    try FileManager.default.createDirectory(at: standard, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try Data("- id: tool-fs\n  name: '@deepseek-ai/dsh-tool-fs'\n".utf8).write(to: outside.appendingPathComponent("agent.cordis.yml"))
    try Data("name: Standard\n".utf8).write(to: standard.appendingPathComponent("preset.yml"))
    try FileManager.default.createSymbolicLink(
        at: standard.appendingPathComponent("agent.cordis.yml"),
        withDestinationURL: outside.appendingPathComponent("agent.cordis.yml")
    )
    try Data("{}".utf8).write(to: root.appendingPathComponent("local-harness-policy.json"))
    defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: outside) }
    #expect(!PresetSecurityPolicy.validatePresetRoot(root))

    try FileManager.default.removeItem(at: standard.appendingPathComponent("agent.cordis.yml"))
    try Data("- id: tool-fs\n  name: '@deepseek-ai/dsh-tool-fs'\n".utf8).write(to: standard.appendingPathComponent("agent.cordis.yml"))
    try Data("unexpected".utf8).write(to: root.appendingPathComponent(".hidden-preset"))
    #expect(!PresetSecurityPolicy.validatePresetRoot(root))
}

@Test func presetPolicyRejectsDefaultOrProjectSkillRootsEvenWithMatchingDigest() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let standard = root.appendingPathComponent("standard", isDirectory: true)
    try FileManager.default.createDirectory(at: standard, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let composition = """
    - id: tool-fs
      name: '@deepseek-ai/dsh-tool-fs'
    - id: skill-filesystem
      name: '@deepseek-ai/dsh-skill-filesystem'
      config:
        includeDefaultRoots: true

    """
    try Data(composition.utf8).write(to: standard.appendingPathComponent("agent.cordis.yml"))
    try Data("name: Unsafe\n".utf8).write(to: standard.appendingPathComponent("preset.yml"))
    let digest = SHA256.hash(data: Data(composition.utf8)).map { String(format: "%02x", $0) }.joined()
    let manifest = "{\"version\":1,\"allowedPresetIDs\":[\"standard\"],\"removedRowIDs\":[\"tool-ralph\",\"tool-workflow\",\"workflow-worker-thread\"],\"compositionSHA256\":\"\(digest)\"}"
    try Data(manifest.utf8).write(to: root.appendingPathComponent("local-harness-policy.json"))

    #expect(!PresetSecurityPolicy.validatePresetRoot(root))
}

@Test func presetPolicyRejectsForbiddenCapabilityInsideAllowedPreset() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    for identifier in ["standard"] {
        let directory = root.appendingPathComponent(identifier, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let marker = "@deepseek-ai/dsh-tool-workflow"
        try Data("- id: capability\n  name: '\(marker)'\n".utf8)
            .write(to: directory.appendingPathComponent("agent.cordis.yml"))
    }
    #expect(!PresetSecurityPolicy.validatePresetRoot(root))
}

@Test func unreviewedBuiltInPackageIsNotAutomaticallyTrusted() throws {
    let temporary = try makeAdmissibleApplicationSupportTestRoot(prefix: "FulmarUnreviewedPlugin")
    let support = temporary.appendingPathComponent("support", isDirectory: true)
    let profiles = temporary.appendingPathComponent("profiles")
    let web = profiles.appendingPathComponent("web")
    try FileManager.default.createDirectory(at: web, withIntermediateDirectories: true)
    try Data("- id: unsafe\n  name: '@deepseek-ai/dsh-fs-local'\n".utf8)
        .write(to: web.appendingPathComponent("cordis.patch.yml"))
    defer { try? FileManager.default.removeItem(at: temporary) }
    let finding = try #require(PluginTrustStore(applicationSupport: support, profileRoot: profiles).audit().first)
    #expect(finding.name == "@deepseek-ai/dsh-fs-local")
    #expect(finding.status == .blocked)
}

@Test func cleanHarnessHomeDoesNotReadOrImportMachineWideProviderState() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(at: legacy.appendingPathComponent("sessions/one"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: legacy.appendingPathComponent("profiles/web"), withIntermediateDirectories: true)
    try Data("llm-pi-ai: {}\n".utf8).write(to: legacy.appendingPathComponent("settings.yaml"))
    try Data("history\n".utf8).write(to: legacy.appendingPathComponent("sessions/one/events.jsonl"))
    try Data("- id: hostile\n".utf8).write(to: legacy.appendingPathComponent("cordis.patch.yml"))
    try Data("plugin".utf8).write(to: legacy.appendingPathComponent("profiles/web/package.json"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(root: isolated, legacyRoot: legacy)
    try manager.prepare()

    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("settings.yaml").path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("sessions").path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("cordis.patch.yml").path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("profiles").path))
    #expect(FileManager.default.fileExists(atPath: isolated.appendingPathComponent(".local-harness-home.json").path))
    #expect(try String(contentsOf: legacy.appendingPathComponent("settings.yaml"), encoding: .utf8) == "llm-pi-ai: {}\n")
    #expect(try String(contentsOf: legacy.appendingPathComponent("sessions/one/events.jsonl"), encoding: .utf8) == "history\n")
}

@Test func isolatedHarnessHomeReclaimsOnlyEmptyPrivateDSHTemporaryDirectories() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-runtime-temp-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let runtimeTemporary = isolated.appendingPathComponent("Temp", isDirectory: true)
    let emptySpill = runtimeTemporary.appendingPathComponent("dsh-spill-empty", isDirectory: true)
    let emptySubprocess = runtimeTemporary.appendingPathComponent("dsh-subprocess-empty", isDirectory: true)
    let nonempty = runtimeTemporary.appendingPathComponent("dsh-spill-retained", isDirectory: true)
    let unrelated = runtimeTemporary.appendingPathComponent("user-owned-empty", isDirectory: true)
    let prefixFile = runtimeTemporary.appendingPathComponent("dsh-subprocess-file", isDirectory: false)
    let outside = temporary.appendingPathComponent("outside", isDirectory: true)
    let linked = runtimeTemporary.appendingPathComponent("dsh-spill-link", isDirectory: false)
    try FileManager.default.createDirectory(at: runtimeTemporary, withIntermediateDirectories: true)
    for directory in [emptySpill, emptySubprocess, nonempty, unrelated, outside] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data("retained".utf8).write(to: nonempty.appendingPathComponent("payload"))
    try Data("not a directory".utf8).write(to: prefixFile)
    try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: outside)
    defer { try? FileManager.default.removeItem(at: temporary) }

    try HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true)
    ).prepare()

    #expect(!FileManager.default.fileExists(atPath: emptySpill.path))
    #expect(!FileManager.default.fileExists(atPath: emptySubprocess.path))
    #expect(FileManager.default.fileExists(atPath: nonempty.path))
    #expect(FileManager.default.fileExists(atPath: unrelated.path))
    #expect(FileManager.default.fileExists(atPath: prefixFile.path))
    #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: linked.path)) != nil)
    #expect(FileManager.default.fileExists(atPath: outside.path))
}

@Test func isolatedHarnessHomeBoundsRuntimeTemporaryDirectoryEnumeration() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-runtime-temp-bound-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let runtimeTemporary = isolated.appendingPathComponent("Temp", isDirectory: true)
    try FileManager.default.createDirectory(at: runtimeTemporary, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    for index in 0..<3 {
        try FileManager.default.createDirectory(
            at: runtimeTemporary.appendingPathComponent("unrelated-\(index)", isDirectory: true),
            withIntermediateDirectories: false
        )
    }
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true),
        limits: .init(maximumRuntimeTemporaryEntries: 2)
    )
    #expect(throws: HarnessHomeError.preparationLimitExceeded("runtime temporary entry count")) {
        try manager.prepare()
    }
}

@Test func isolatedHarnessHomeRejectsCompositionOverrides() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data("- insert: [{ id: unsafe }]\n".utf8).write(to: isolated.appendingPathComponent("cordis.patch.yml"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(root: isolated, legacyRoot: temporary.appendingPathComponent("missing"))
    #expect(throws: HarnessHomeError.self) { try manager.prepare() }
}

@Test func isolatedHarnessHomeAcceptsExactReviewedWebProfile() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let profile = isolated.appendingPathComponent("profiles/web", isDirectory: true)
    try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data("# comments are allowed\n[]\n".utf8).write(to: profile.appendingPathComponent("cordis.patch.yml"))
    let package: [String: Any] = [
        "dependencies": [String: String](),
        "dsh": ["profile": ["bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]]]
    ]
    try JSONSerialization.data(withJSONObject: package).write(to: profile.appendingPathComponent("package.json"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(root: isolated, legacyRoot: temporary.appendingPathComponent("missing"))
    try manager.prepare()
}

@Test func isolatedHarnessHomeBoundsMutableProfileReadsBeforeParsing() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let profile = isolated.appendingPathComponent("profiles/web", isDirectory: true)
    try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    let package = profile.appendingPathComponent("package.json")
    try Data(repeating: 0x20, count: 65).write(to: package)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let limits = HarnessHomeManager.Limits(
        maximumProfileFileBytes: 64,
        maximumProfileAggregateBytes: 128
    )
    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing"),
        limits: limits
    )
    #expect(throws: HarnessHomeError.profileInputTooLarge("web/package.json")) {
        try manager.prepare()
    }

    try FileManager.default.removeItem(at: package)
    try Data(repeating: 0x20, count: 65).write(to: profile.appendingPathComponent("cordis.patch.yml"))
    #expect(throws: HarnessHomeError.profileInputTooLarge("web/cordis.patch.yml")) {
        try manager.prepare()
    }
}

@Test func cleanHarnessHomeIgnoresMachineWideProviderFileSizes() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
    try Data(repeating: 0x41, count: 9).write(to: legacy.appendingPathComponent("settings.yaml"))
    defer { try? FileManager.default.removeItem(at: temporary) }
    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: legacy,
        limits: .init(maximumMigrationFileBytes: 8, maximumMigrationBytes: 8)
    )
    try manager.prepare()
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("settings.yaml").path))
    #expect(FileManager.default.fileExists(atPath: isolated.appendingPathComponent(".local-harness-home.json").path))
    #expect((try Data(contentsOf: legacy.appendingPathComponent("settings.yaml"))).count == 9)
}

@Test func cleanHarnessHomeDoesNotEnumerateMachineWideDirectoryFloods() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let sessions = legacy.appendingPathComponent("sessions", isDirectory: true)
    let attachments = legacy.appendingPathComponent("attachments", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(at: sessions, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: attachments, withIntermediateDirectories: true)
    try Data("already copied before the later flood".utf8)
        .write(to: attachments.appendingPathComponent("safe.txt"))
    for index in 0..<5 {
        try FileManager.default.createDirectory(
            at: sessions.appendingPathComponent("empty-\(index)", isDirectory: true),
            withIntermediateDirectories: false
        )
    }
    defer { try? FileManager.default.removeItem(at: temporary) }
    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: legacy,
        limits: .init(maximumMigrationNodes: 4)
    )
    try manager.prepare()
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("sessions").path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("attachments").path))
    #expect(FileManager.default.fileExists(atPath: isolated.appendingPathComponent(".local-harness-home.json").path))
    #expect(FileManager.default.fileExists(atPath: attachments.appendingPathComponent("safe.txt").path))
    #expect(FileManager.default.fileExists(atPath: sessions.appendingPathComponent("empty-4").path))
}

@Test func cleanHarnessHomeDoesNotTraverseMachineWideDepthOrPaths() throws {
    let depthRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let depthLegacy = depthRoot.appendingPathComponent("legacy", isDirectory: true)
    let depthHome = depthRoot.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(
        at: depthLegacy.appendingPathComponent("sessions/a/b/c", isDirectory: true),
        withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: depthRoot) }
    try HarnessHomeManager(
        root: depthHome,
        legacyRoot: depthLegacy,
        limits: .init(maximumMigrationDepth: 2)
    ).prepare()
    #expect(!FileManager.default.fileExists(atPath: depthHome.appendingPathComponent("sessions").path))

    let pathRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let pathLegacy = pathRoot.appendingPathComponent("legacy", isDirectory: true)
    let pathHome = pathRoot.appendingPathComponent("isolated", isDirectory: true)
    try FileManager.default.createDirectory(
        at: pathLegacy.appendingPathComponent("sessions/abcdefghijkl", isDirectory: true),
        withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: pathRoot) }
    try HarnessHomeManager(
        root: pathHome,
        legacyRoot: pathLegacy,
        limits: .init(maximumRelativePathBytes: 16)
    ).prepare()
    #expect(!FileManager.default.fileExists(atPath: pathHome.appendingPathComponent("sessions").path))
}

@Test func isolatedHarnessHomeUsesOneMonotonicPreparationDeadline() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let started = DispatchTime.now().uptimeNanoseconds
    #expect(throws: HarnessHomeError.preparationLimitExceeded("monotonic deadline")) {
        try HarnessHomeManager(
            root: temporary.appendingPathComponent("isolated", isDirectory: true),
            legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true),
            limits: .init(preparationDuration: 0)
        ).prepare()
    }
    #expect(DispatchTime.now().uptimeNanoseconds - started < 1_000_000_000)
    #expect(!FileManager.default.fileExists(atPath: temporary.appendingPathComponent("isolated").path))
}

@Test func isolatedHarnessHomeRecoversEveryAtomicMigrationCrashBoundary() throws {
    for phase in [
        HarnessHomeMigrationPhase.stagingCreated,
        .contentDurable,
        .receiptDurable,
        .installed
    ] {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("home-migration-\(UUID().uuidString)", isDirectory: true)
        let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
        let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
        try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
        try Data("before-crash".utf8).write(to: legacy.appendingPathComponent("settings.yaml"))
        defer { try? FileManager.default.removeItem(at: temporary) }

        let interrupted = HarnessHomeManager(
            root: isolated,
            legacyRoot: legacy,
            migrationCrashHook: { $0 == phase }
        )
        #expect(throws: HarnessHomeMigrationTestInterruption.simulatedCrash(phase)) {
            try interrupted.prepare()
        }

        try Data("after-crash".utf8).write(to: legacy.appendingPathComponent("settings.yaml"))
        try HarnessHomeManager(root: isolated, legacyRoot: legacy).prepare()
        #expect(!FileManager.default.fileExists(
            atPath: isolated.appendingPathComponent("settings.yaml").path
        ))
        #expect(try String(
            contentsOf: legacy.appendingPathComponent("settings.yaml"),
            encoding: .utf8
        ) == "after-crash")
        #expect(FileManager.default.fileExists(
            atPath: isolated.appendingPathComponent(".local-harness-home.json").path
        ))
        #expect(!FileManager.default.fileExists(
            atPath: temporary.appendingPathComponent(".local-harness-home-migration-v1").path
        ))
    }
}

@Test func currentHarnessHomeDiscardsOnlyAnExactCurrentCleanInstallStaging() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-current-staging-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let staging = temporary.appendingPathComponent(".local-harness-home-migration-v1", isDirectory: true)
    try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: false)
    for directory in [isolated, staging] {
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        try writeValidHarnessHomeReceipt(at: directory)
    }
    defer { try? FileManager.default.removeItem(at: temporary) }

    try HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true)
    ).prepare()
    #expect(!FileManager.default.fileExists(atPath: staging.path))
    #expect(FileManager.default.fileExists(atPath: isolated.path))
}

@Test func unrecognizedStagingBesideCurrentHomeIsPreservedWithoutChildRemoval() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-unknown-staging-current-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let staging = temporary.appendingPathComponent(".local-harness-home-migration-v1", isDirectory: true)
    let unknown = staging.appendingPathComponent("sessions/private/events.jsonl")
    try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(
        at: unknown.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: isolated.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: staging.path)
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data("opaque-history".utf8).write(to: unknown)
    defer { try? FileManager.default.removeItem(at: temporary) }

    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(
            root: isolated,
            legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true)
        ).prepare()
    }
    #expect(try String(contentsOf: unknown, encoding: .utf8) == "opaque-history")
    #expect(FileManager.default.fileExists(atPath: isolated.path))
}

@Test func receiptlessAndFutureMigrationStagingFailClosedAndRemainOpaque() throws {
    let futureVersions: [Int?] = [nil, 4]
    for futureVersion in futureVersions {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("home-unknown-staging-\(UUID().uuidString)", isDirectory: true)
        let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
        let staging = temporary.appendingPathComponent(
            ".local-harness-home-migration-v1",
            isDirectory: true
        )
        let unknown = staging.appendingPathComponent("attachments/private.bin")
        try FileManager.default.createDirectory(
            at: unknown.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: staging.path)
        try Data("opaque-provider-state".utf8).write(to: unknown)
        if let futureVersion {
            let receipt: [String: Any] = [
                "version": futureVersion,
                "migratedAt": 0.0,
                "copiedEntries": [String](),
                "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current + 1
            ]
            let receiptURL = staging.appendingPathComponent(".local-harness-home.json")
            try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
                .write(to: receiptURL)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: receiptURL.path
            )
        }
        defer { try? FileManager.default.removeItem(at: temporary) }

        #expect(throws: HarnessHomeError.self) {
            try HarnessHomeManager(
                root: isolated,
                legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true)
            ).prepare()
        }
        #expect(!FileManager.default.fileExists(atPath: isolated.path))
        #expect(try String(contentsOf: unknown, encoding: .utf8) == "opaque-provider-state")
    }
}

@Test func isolatedHarnessHomePreservesFormerReceiptlessPartialCopyWithinBounds() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-partial-\(UUID().uuidString)", isDirectory: true)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let staleSessions = isolated.appendingPathComponent("sessions", isDirectory: true)
    try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: staleSessions, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: isolated.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: staleSessions.path)
    let stale = staleSessions.appendingPathComponent("partial.jsonl")
    try Data("never committed".utf8).write(to: stale)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stale.path)
    try Data("fresh legacy".utf8).write(to: legacy.appendingPathComponent("settings.yaml"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: legacy,
        recoveryAuthenticationKey: Data(repeating: 0x61, count: 32)
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try manager.prepare()
        Issue.record("Receiptless homes must require an explicit recovery decision")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let value) {
        request = value
    }
    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect(!FileManager.default.fileExists(atPath: stale.path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("settings.yaml").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("sessions/partial.jsonl").path))
    #expect(FileManager.default.fileExists(atPath: legacy.appendingPathComponent("settings.yaml").path))
}

@Test func isolatedHarnessHomeOpaquelyPreservesFormerHomePermissions() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-legacy-permissions-\(UUID().uuidString)", isDirectory: true)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let staleSessions = isolated.appendingPathComponent("sessions", isDirectory: true)
    try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: staleSessions, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: isolated.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: staleSessions.path)
    let stale = staleSessions.appendingPathComponent("partial.jsonl")
    try Data("never committed".utf8).write(to: stale)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: stale.path)
    let legacySettings = legacy.appendingPathComponent("settings.yaml")
    try Data("fresh legacy".utf8).write(to: legacySettings)
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: legacy,
        recoveryAuthenticationKey: Data(repeating: 0x62, count: 32)
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try manager.prepare()
        Issue.record("Receiptless homes must require an explicit recovery decision")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let value) {
        request = value
    }
    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect(!FileManager.default.fileExists(atPath: stale.path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("settings.yaml").path))
    let rootMode = try #require(
        FileManager.default.attributesOfItem(atPath: isolated.path)[.posixPermissions] as? NSNumber
    )
    let preserved = receipt.quarantine.appendingPathComponent("sessions/partial.jsonl")
    let preservedMode = try #require(
        FileManager.default.attributesOfItem(
            atPath: preserved.path
        )[.posixPermissions] as? NSNumber
    )
    #expect(rootMode.intValue == 0o700)
    #expect(preservedMode.intValue == 0o644)
}

@Test func isolatedHarnessHomeDoesNotTraverseWritableHistoricalChildren() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-unsafe-legacy-permissions-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let sessions = isolated.appendingPathComponent("sessions", isDirectory: true)
    try FileManager.default.createDirectory(at: sessions, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: isolated.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: sessions.path)
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true),
        recoveryAuthenticationKey: Data(repeating: 0x63, count: 32)
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try manager.prepare()
        Issue.record("Receiptless homes must require an explicit recovery decision")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let value) {
        request = value
    }
    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(
        request,
        choice: .startClean
    )
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()
    #expect(!FileManager.default.fileExists(atPath: sessions.path))
    #expect(FileManager.default.fileExists(
        atPath: receipt.quarantine.appendingPathComponent("sessions").path
    ))
}

@Test func isolatedHarnessHomeRecoversOnlyTheExactEmptyEarlySkillsScaffold() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-empty-skills-\(UUID().uuidString)", isDirectory: true)
    let legacy = temporary.appendingPathComponent("legacy", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let skills = isolated.appendingPathComponent("skills", isDirectory: true)
    let active = skills.appendingPathComponent("Active", isDirectory: true)
    let packages = skills.appendingPathComponent("Packages", isDirectory: true)
    try FileManager.default.createDirectory(at: active, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: packages, withIntermediateDirectories: true)
    for directory in [isolated, skills, active, packages] {
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)
    try Data("fresh legacy".utf8).write(to: legacy.appendingPathComponent("settings.yaml"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: legacy,
        recoveryAuthenticationKey: Data(repeating: 0x64, count: 32)
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try manager.prepare()
        Issue.record("Receiptless homes must require an explicit recovery decision")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let value) {
        request = value
    }
    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()

    #expect(!FileManager.default.fileExists(atPath: skills.path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("skills/Active").path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("skills/Packages").path))
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("settings.yaml").path))
}

@Test func isolatedHarnessHomePreservesANonemptyEarlySkillsScaffold() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-nonempty-skills-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let packages = isolated.appendingPathComponent("skills/Packages", isDirectory: true)
    try FileManager.default.createDirectory(at: packages, withIntermediateDirectories: true)
    for directory in [isolated, isolated.appendingPathComponent("skills"), packages] {
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    let retained = packages.appendingPathComponent("user-skill")
    try FileManager.default.createDirectory(at: retained, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: retained.path)
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing", isDirectory: true),
        recoveryAuthenticationKey: Data(repeating: 0x65, count: 32)
    )
    let request: HarnessHomeReceiptlessRecoveryRequest
    do {
        try manager.prepare()
        Issue.record("Receiptless homes must require an explicit recovery decision")
        return
    } catch HarnessHomeError.receiptlessRecoveryRequired(let value) {
        request = value
    }
    let receipt = try manager.recoverReceiptlessHomeAfterExplicitConfirmation(request, choice: .settingsOnly)
    try manager.acknowledgePublishedReceiptlessRecovery(receipt)
    try manager.prepare()
    #expect(!FileManager.default.fileExists(atPath: retained.path))
    #expect(FileManager.default.fileExists(atPath: receipt.quarantine.appendingPathComponent("skills/Packages/user-skill").path))
}

@Test func harnessControllerCannotMaterializeSkillsBeforeHomePreparation() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("controller-preparation-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: temporary) }
    let controller = HarnessController(applicationSupportDirectory: temporary)

    #expect(throws: (any Error).self) { try controller.skillsTrustStore() }
    #expect(!FileManager.default.fileExists(
        atPath: temporary.appendingPathComponent("HarnessHome", isDirectory: true).path
    ))
}

@Test func isolatedHarnessHomeStrictlyBoundsAndValidatesMigrationReceipt() throws {
    let temporary = FileManager.default.temporaryDirectory
        .appendingPathComponent("home-receipt-\(UUID().uuidString)", isDirectory: true)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let missing = temporary.appendingPathComponent("missing", isDirectory: true)
    try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: isolated.path)
    let receipt = isolated.appendingPathComponent(".local-harness-home.json")
    try Data("{}".utf8).write(to: receipt)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    defer { try? FileManager.default.removeItem(at: temporary) }

    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(root: isolated, legacyRoot: missing).prepare()
    }

    try FileManager.default.removeItem(at: receipt)
    try Data(repeating: 0x20, count: 64 * 1_024 + 1).write(to: receipt)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(root: isolated, legacyRoot: missing).prepare()
    }

    try FileManager.default.removeItem(at: receipt)
    try writeValidHarnessHomeReceipt(
        at: isolated,
        source: "/wrong/source",
        copiedEntries: ["settings.yaml"]
    )
    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(root: isolated, legacyRoot: missing).prepare()
    }
}

@Test func isolatedHarnessHomeRejectsLinkedCriticalState() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let outside = temporary.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    let outsideSettings = outside.appendingPathComponent("settings.yaml")
    try Data("{}".utf8).write(to: outsideSettings)
    try FileManager.default.createSymbolicLink(
        at: isolated.appendingPathComponent("settings.yaml"),
        withDestinationURL: outsideSettings
    )
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(root: isolated, legacyRoot: temporary.appendingPathComponent("missing"))
    #expect(throws: HarnessHomeError.self) { try manager.prepare() }
}

@Test func isolatedHarnessHomeRejectsLinkedRootOrProfile() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let realHome = temporary.appendingPathComponent("real-home", isDirectory: true)
    let linkedHome = temporary.appendingPathComponent("linked-home", isDirectory: true)
    try FileManager.default.createDirectory(at: realHome, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: linkedHome, withDestinationURL: realHome)
    defer { try? FileManager.default.removeItem(at: temporary) }
    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(root: linkedHome, legacyRoot: temporary.appendingPathComponent("missing")).prepare()
    }

    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let outsideProfile = temporary.appendingPathComponent("outside-profile", isDirectory: true)
    try FileManager.default.createDirectory(at: isolated.appendingPathComponent("profiles"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outsideProfile, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    try FileManager.default.createSymbolicLink(
        at: isolated.appendingPathComponent("profiles/web"),
        withDestinationURL: outsideProfile
    )
    #expect(throws: HarnessHomeError.self) {
        try HarnessHomeManager(root: isolated, legacyRoot: temporary.appendingPathComponent("missing")).prepare()
    }
}

@Test func isolatedHarnessHomeRejectsProfileLocalModuleShadow() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let shadow = isolated.appendingPathComponent(
        "profiles/web/node_modules/@deepseek-ai/dsh-credentials",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: shadow, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data("{}".utf8).write(to: shadow.appendingPathComponent("package.json"))
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(root: isolated, legacyRoot: temporary.appendingPathComponent("missing"))
    #expect(throws: HarnessHomeError.self) { try manager.prepare() }
}

@Test func isolatedHarnessHomeSafelyRebuildsOnlySymlinkFallbackCaches() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let isolated = temporary.appendingPathComponent("isolated", isDirectory: true)
    let runtime = temporary.appendingPathComponent("runtime", isDirectory: true)
    let package = runtime.appendingPathComponent("node_modules/@local-harness/safe", isDirectory: true)
    let fallbackScope = isolated.appendingPathComponent("profiles/node_modules/@local-harness", isDirectory: true)
    try FileManager.default.createDirectory(at: package, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: fallbackScope, withIntermediateDirectories: true)
    try writeValidHarnessHomeReceipt(at: isolated)
    try Data(#"{"name":"@local-harness/safe","version":"1.0.0"}"#.utf8)
        .write(to: package.appendingPathComponent("package.json"))
    let link = fallbackScope.appendingPathComponent("safe")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: package)
    defer { try? FileManager.default.removeItem(at: temporary) }

    let manager = HarnessHomeManager(
        root: isolated,
        legacyRoot: temporary.appendingPathComponent("missing")
    )
    try manager.prepare()
    #expect(!FileManager.default.fileExists(atPath: isolated.appendingPathComponent("profiles/node_modules").path))

    let unsafePackage = isolated.appendingPathComponent("profiles/node_modules/@local-harness/unsafe", isDirectory: true)
    try FileManager.default.createDirectory(at: unsafePackage, withIntermediateDirectories: true)
    #expect(throws: HarnessHomeError.self) { try manager.prepare() }
}

private func writeValidHarnessHomeReceipt(
    at root: URL,
    source: String? = nil,
    copiedEntries: [String] = []
) throws {
    var receipt: [String: Any] = [
        "version": ProviderHistoryPrivacyEpoch.currentHarnessHomeReceiptVersion,
        "migratedAt": 0.0,
        "copiedEntries": copiedEntries,
        "providerHistoryPrivacyEpoch": ProviderHistoryPrivacyEpoch.current
    ]
    if let source {
        receipt["source"] = source
        receipt["sourceKind"] = "historicalProviderState"
    }
    let url = root.appendingPathComponent(".local-harness-home.json")
    try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys]).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
