import Darwin
import Foundation
import Testing
@testable import LocalHarness

private struct HarnessRuntimeSandboxFixture {
    let root: URL
    let support: URL
    let home: URL
    let workspace: URL
    let telemetry: URL
    let receipt: URL
    let mutationPolicy: URL
    let skills: URL
    let profileModules: URL
    let profileManifest: URL
    let backups: URL
    let control: URL
}

private func makeHarnessRuntimeSandboxFixture() throws -> HarnessRuntimeSandboxFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "fulmar-runtime-write-sandbox-\(UUID().uuidString)",
        isDirectory: true
    )
    let support = root.appendingPathComponent("Application Support", isDirectory: true)
    let home = support.appendingPathComponent("HarnessHome", isDirectory: true)
    let workspace = support.appendingPathComponent("Workspace", isDirectory: true)
    let telemetry = support.appendingPathComponent("PerformanceTelemetry", isDirectory: true)
    let backups = support.appendingPathComponent("Backups", isDirectory: true)
    let control = support.appendingPathComponent(".FulmarControl", isDirectory: true)
    let skills = home.appendingPathComponent("skills/Active", isDirectory: true)
    let profile = home.appendingPathComponent("profiles/web", isDirectory: true)
    let profileModules = profile.appendingPathComponent("node_modules", isDirectory: true)
    for directory in [root, support, home, workspace, telemetry, backups, control,
                      home.appendingPathComponent("skills", isDirectory: true), skills,
                      home.appendingPathComponent("profiles", isDirectory: true), profile,
                      profileModules] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }
    let receipt = home.appendingPathComponent(ProviderHistoryPrivacyEpoch.ownershipReceiptName)
    let mutationPolicy = home.appendingPathComponent(WorkspaceMutationPolicyStore.fileName)
    let profileManifest = profile.appendingPathComponent("package.json")
    try Data("trusted".utf8).write(to: receipt, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
    try Data("policy".utf8).write(to: mutationPolicy, options: .withoutOverwriting)
    try Data("skill".utf8).write(
        to: skills.appendingPathComponent("trusted"), options: .withoutOverwriting
    )
    try Data("manifest".utf8).write(to: profileManifest, options: .withoutOverwriting)
    try Data("module".utf8).write(
        to: profileModules.appendingPathComponent("trusted"),
        options: .withoutOverwriting
    )
    try Data("backup".utf8).write(
        to: backups.appendingPathComponent("protected"),
        options: .withoutOverwriting
    )
    try Data("anchor".utf8).write(
        to: control.appendingPathComponent("protected"),
        options: .withoutOverwriting
    )
    return HarnessRuntimeSandboxFixture(
        root: root,
        support: support,
        home: home,
        workspace: workspace,
        telemetry: telemetry,
        receipt: receipt,
        mutationPolicy: mutationPolicy,
        skills: skills,
        profileModules: profileModules,
        profileManifest: profileManifest,
        backups: backups,
        control: control
    )
}

@Test func harnessRuntimeOuterSandboxAllowsRuntimeStateButDeniesNativeControlWrites() throws {
    let fixture = try makeHarnessRuntimeSandboxFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let boundary = try HarnessRuntimeWriteSandbox.prepare(
        applicationSupport: fixture.support,
        harnessHome: fixture.home,
        workspace: fixture.workspace,
        telemetryDirectory: fixture.telemetry
    )
    let script = #"""
set -u
printf session > "$1/session-ok"
printf workspace > "$2/workspace-ok"
printf telemetry > "$3/telemetry-ok"
if printf forged > "$4" 2>/dev/null; then exit 41; fi
if mv "$4" "$1/moved-receipt" 2>/dev/null; then exit 42; fi
if printf forged > "$5/protected" 2>/dev/null; then exit 43; fi
if printf forged > "$6/protected" 2>/dev/null; then exit 44; fi
if printf forged > "$7" 2>/dev/null; then exit 45; fi
if printf forged > "$8/trusted" 2>/dev/null; then exit 46; fi
if printf forged > "$9" 2>/dev/null; then exit 47; fi
if printf forged > "${10}/trusted" 2>/dev/null; then exit 48; fi
exit 0
"""#
    let wrapped = try boundary.wrappedLaunch(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
            "-c", script, "fulmar-runtime-write-sandbox",
            fixture.home.path,
            fixture.workspace.path,
            fixture.telemetry.path,
            fixture.receipt.path,
            fixture.backups.path,
            fixture.control.path,
            fixture.mutationPolicy.path,
            fixture.skills.path,
            fixture.profileManifest.path,
            fixture.profileModules.path
        ]
    )
    let process = Process()
    process.executableURL = wrapped.executable
    process.arguments = wrapped.arguments
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    #expect(boundedTestWaitForExit(process, timeout: 10))
    #expect(process.terminationReason == .exit)
    #expect(process.terminationStatus == 0)
    #expect(try String(contentsOf: fixture.home.appendingPathComponent("session-ok"), encoding: .utf8) == "session")
    #expect(try String(contentsOf: fixture.workspace.appendingPathComponent("workspace-ok"), encoding: .utf8) == "workspace")
    #expect(try String(contentsOf: fixture.telemetry.appendingPathComponent("telemetry-ok"), encoding: .utf8) == "telemetry")
    #expect(try String(contentsOf: fixture.receipt, encoding: .utf8) == "trusted")
    #expect(try String(contentsOf: fixture.backups.appendingPathComponent("protected"), encoding: .utf8) == "backup")
    #expect(try String(contentsOf: fixture.control.appendingPathComponent("protected"), encoding: .utf8) == "anchor")
    #expect(try String(contentsOf: fixture.mutationPolicy, encoding: .utf8) == "policy")
    #expect(try String(contentsOf: fixture.skills.appendingPathComponent("trusted"), encoding: .utf8) == "skill")
    #expect(try String(contentsOf: fixture.profileManifest, encoding: .utf8) == "manifest")
    #expect(try String(contentsOf: fixture.profileModules.appendingPathComponent("trusted"), encoding: .utf8) == "module")
    #expect(!FileManager.default.fileExists(atPath: fixture.home.appendingPathComponent("moved-receipt").path))

    // Exercise the real pinned boot functions, not just touch/printf probes.
    // The old unconditional mkdir on profiles/node_modules failed even when
    // the native side had already created the directory. Both a fresh profile
    // and a second boot must work without allowing runtime composition writes.
    try FileManager.default.removeItem(at: fixture.profileManifest)
    try FileManager.default.removeItem(at: fixture.profileModules.appendingPathComponent("trusted"))
    let project = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let node = project.appendingPathComponent("VendorRuntime/node-v22.23.1-darwin-arm64/bin/node")
    let boot = project.appendingPathComponent("VendorRuntime/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js")
    let anchor = project.appendingPathComponent("VendorRuntime/node_modules/@deepseek-ai/dsh/package.json")
    let bootScript = #"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const [entry, anchor, home, protectedRun] = process.argv.slice(1);
process.umask(0o077);
const { healProfilesModuleFallback, loadProfile } = await import(pathToFileURL(entry).href);
healProfilesModuleFallback(anchor, home);
const profile = loadProfile('dsh', 'web', anchor, home);
assert.equal(profile.dir, home + '/profiles/web');
assert.deepEqual(profile.layers.map(layer => layer.packageName),
  ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']);
if (protectedRun === 'yes') {
  for (const target of [home + '/profiles/web/package.json',
      home + '/profiles/web/cordis.patch.yml', home + '/profiles/node_modules/forged.js',
      home + '/profiles/web/node_modules/forged.js']) {
    assert.throws(() => fs.writeFileSync(target, 'forged'), error => error.code === 'EPERM' || error.code === 'EACCES');
  }
  fs.writeFileSync(home + '/profiles/web/cordis.yml', '# runtime composition\n');
}
"""#
    let baseArguments = ["--input-type=module", "-e", bootScript, boot.path, anchor.path, fixture.home.path]
    let bootEnvironment = ["PATH": "/usr/bin:/bin", "HOME": fixture.home.path, "DSH_HOME": fixture.home.path]
    #expect(try SandboxBoundaryProbeProcess.run(
        executable: node,
        arguments: baseArguments + ["no"],
        currentDirectory: fixture.workspace,
        environment: bootEnvironment,
        deadline: 15
    ) == 0)
    let manifestBefore = try Data(contentsOf: fixture.profileManifest)
    let protectedBoot = try boundary.wrappedLaunch(executable: node, arguments: baseArguments + ["yes"])
    for _ in 0..<2 {
        #expect(try SandboxBoundaryProbeProcess.run(
            executable: protectedBoot.executable,
            arguments: protectedBoot.arguments,
            currentDirectory: fixture.workspace,
            environment: bootEnvironment,
            deadline: 15
        ) == 0)
        #expect(try Data(contentsOf: fixture.profileManifest) == manifestBefore)
    }

    // Exercise the actual native preparation wrapper as well as the boot
    // exports above. Foundation's nullDevice has fd -1 on Darwin; passing
    // that descriptor to the raw spawn runner used to fail before JS ran.
    // Use the checkout's ignored build namespace rather than /private/tmp:
    // the retained capability rejects Foundation's /tmp alias normalization.
    let nativeRoot = project.appendingPathComponent(
        "build/native-profile-wrapper-\(UUID().uuidString)", isDirectory: true
    )
    defer { try? FileManager.default.removeItem(at: nativeRoot) }
    let resources = nativeRoot.appendingPathComponent("Resources", isDirectory: true)
    let nativeHome = nativeRoot.appendingPathComponent("HarnessHome", isDirectory: true)
    let nativeWorkspace = nativeRoot.appendingPathComponent("Workspace", isDirectory: true)
    let temporary = nativeHome.appendingPathComponent("Temp", isDirectory: true)
    for directory in [nativeRoot, resources, nativeHome, nativeWorkspace, temporary] {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
    }
    let resolvedHomeSpelling = Darwin.realpath(nativeHome.path, nil)
    let homeSpelling = try #require(resolvedHomeSpelling)
    let canonicalHome = URL(fileURLWithPath: String(cString: homeSpelling), isDirectory: true)
    Darwin.free(homeSpelling)
    let preparationScript = resources.appendingPathComponent("PrepareHarnessProfile.mjs")
    let inputProbe = #"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
assert.equal(process.argv.length, 3);
const home = process.argv[2];
assert.equal(fs.realpathSync.native(home), home);
assert.equal(process.env.HOME, home);
assert.equal(fs.realpathSync.native(process.env.TMPDIR), home + '/Temp');
assert.equal(fs.realpathSync.native(process.cwd()), home.replace(/\/HarnessHome$/, '/Workspace'));
assert.equal(process.env.DSH_TELEMETRY_MODE, 'DISABLED');
for (const name of Object.keys(process.env)) {
  assert.ok(!/AUTH|TOKEN|NONCE|CREDENTIAL|API_KEY|SSH_AUTH_SOCK/.test(name));
}
const input = fs.fstatSync(0), nullDevice = fs.statSync('/dev/null');
assert.ok(input.isCharacterDevice());
for (const key of ['dev', 'ino', 'rdev']) assert.equal(input[key], nullDevice[key]);
assert.equal(fs.readSync(0, Buffer.alloc(1), 0, 1, null), 0);
fs.writeFileSync(home + '/native-preparation-input-verified', 'null EOF and private environment');
"""#
    try Data(inputProbe.utf8).write(to: preparationScript, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: preparationScript.path)
    let runPreparation: (URL) throws -> Void = { executable in
        try HarnessProfilePreparation.run(
            node: executable, resources: resources, home: canonicalHome,
            workspace: nativeWorkspace, temporaryDirectory: temporary,
            budget: RuntimeStartupPrerequisiteBudget(
                cancellation: RuntimeStartupPrerequisiteCancellation(), duration: 15
            )
        )
    }
    try runPreparation(node)
    #expect(try String(
        contentsOf: nativeHome.appendingPathComponent("native-preparation-input-verified"), encoding: .utf8
    ) == "null EOF and private environment")

    let privateDiagnostic = "synthetic-private-preparation-diagnostic"
    try Data("process.stderr.write('\(privateDiagnostic)'); process.exit(23);".utf8).write(to: preparationScript)
    do {
        try runPreparation(node)
        Issue.record("A failed preparation must not be accepted")
    } catch HarnessProfilePreparationError.exited(let status) {
        #expect(status == 23)
        let message = HarnessProfilePreparationError.exited(status).localizedDescription
        #expect(message.contains("exit status 23"))
        #expect(!message.contains(privateDiagnostic))
        #expect(!message.contains(nativeRoot.path))
    }
    try Data("process.stderr.write('x'.repeat(32768));".utf8).write(to: preparationScript)
    do {
        try runPreparation(node)
        Issue.record("Oversized preparation diagnostics must remain bounded")
    } catch HarnessProfilePreparationError.boundedLimit(let limit) {
        #expect(limit == .stderrBytes(16 * 1_024))
        #expect(HarnessProfilePreparationError.boundedLimit(limit).localizedDescription
            == "The bundled web-profile preparer exceeded its diagnostic output limit.")
    }
    let nonExecutable = resources.appendingPathComponent("non-executable-node")
    try Data("not executable".utf8).write(to: nonExecutable, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: nonExecutable.path)
    do {
        try runPreparation(nonExecutable)
        Issue.record("A native spawn failure must not be accepted")
    } catch HarnessProfilePreparationError.launchFailed(.spawnFailed(let code)) {
        #expect(code == EACCES)
        #expect(!HarnessProfilePreparationError.launchFailed(.spawnFailed(code))
            .localizedDescription.contains(nativeRoot.path))
    }
}

@Test func harnessRuntimeOuterSandboxRejectsPermissiveLinkedOrUnrelatedRoots() throws {
    let fixture = try makeHarnessRuntimeSandboxFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.workspace.path)
    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.home,
            workspace: fixture.workspace,
            telemetryDirectory: fixture.telemetry
        )
    }
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.workspace.path)
    let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(
        at: outside,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.home,
            workspace: outside,
            telemetryDirectory: fixture.telemetry
        )
    }

    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.support,
            workspace: fixture.workspace,
            telemetryDirectory: fixture.telemetry
        )
    }

    let nestedWorkspace = fixture.home.appendingPathComponent("nested-workspace", isDirectory: true)
    try FileManager.default.createDirectory(
        at: nestedWorkspace,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.home,
            workspace: nestedWorkspace,
            telemetryDirectory: fixture.telemetry
        )
    }

    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.home,
            workspace: fixture.workspace,
            telemetryDirectory: fixture.support
        )
    }
}

@Test func harnessRuntimeOuterSandboxRejectsInvalidWrappedTargetsAndArguments() throws {
    let fixture = try makeHarnessRuntimeSandboxFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let boundary = try HarnessRuntimeWriteSandbox.prepare(
        applicationSupport: fixture.support,
        harnessHome: fixture.home,
        workspace: fixture.workspace,
        telemetryDirectory: fixture.telemetry
    )
    #expect(throws: HarnessRuntimeWriteSandboxError.invalidLaunch) {
        _ = try boundary.wrappedLaunch(
            executable: URL(string: "https://example.invalid/runtime")!,
            arguments: []
        )
    }
    #expect(throws: HarnessRuntimeWriteSandboxError.invalidLaunch) {
        _ = try boundary.wrappedLaunch(
            executable: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["bad\0argument"]
        )
    }
}

@Test func harnessRuntimeOuterSandboxRejectsProfileControlCharacterInjection() throws {
    let fixture = try makeHarnessRuntimeSandboxFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let injected = fixture.support.appendingPathComponent("bad\n(allow file-write*)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: injected,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try HarnessRuntimeWriteSandbox.prepare(
            applicationSupport: fixture.support,
            harnessHome: fixture.home,
            workspace: injected,
            telemetryDirectory: fixture.telemetry
        )
    }
}

@Test func harnessRuntimeOuterSandboxRejectsRootReplacementBeforeExec() throws {
    let fixture = try makeHarnessRuntimeSandboxFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let boundary = try HarnessRuntimeWriteSandbox.prepare(
        applicationSupport: fixture.support,
        harnessHome: fixture.home,
        workspace: fixture.workspace,
        telemetryDirectory: fixture.telemetry
    )
    let displaced = fixture.support.appendingPathComponent("Workspace-displaced", isDirectory: true)
    try FileManager.default.moveItem(at: fixture.workspace, to: displaced)
    try FileManager.default.createDirectory(
        at: fixture.workspace,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    #expect(throws: HarnessRuntimeWriteSandboxError.unsafeRoot) {
        _ = try boundary.wrappedLaunch(
            executable: URL(fileURLWithPath: "/bin/true"),
            arguments: []
        )
    }
}
