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
