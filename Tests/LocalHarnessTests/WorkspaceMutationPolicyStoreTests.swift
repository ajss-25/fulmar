import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Test func workspaceMutationPolicyIsOwnerOnlyAtomicAndRoundTrips() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarWorkspacePolicy-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    let store = WorkspaceMutationPolicyStore(harnessHome: root)

    try store.requireCheckpoint()
    #expect(try store.load().mode == .readOnly)
    try store.allowProtectedMutation()
    #expect(try store.load() == WorkspaceMutationPolicy(
        schemaVersion: 1,
        mode: .readWrite,
        reason: .protectedCheckpoint
    ))

    let policy = root.appendingPathComponent(WorkspaceMutationPolicyStore.fileName)
    var metadata = stat()
    #expect(Darwin.lstat(policy.path, &metadata) == 0)
    #expect(metadata.st_mode & S_IFMT == S_IFREG)
    #expect(metadata.st_uid == geteuid())
    #expect(metadata.st_nlink == 1)
    #expect(Int(metadata.st_mode) & 0o077 == 0)
    let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path)
        .filter { $0.hasSuffix(".tmp") }
    #expect(leftovers.isEmpty)
}

@Test func workspaceMutationPolicyRefusesLinkedPolicyAndUnsafeHome() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarWorkspacePolicyHostile-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let home = root.appendingPathComponent("home", isDirectory: true)
    let outside = root.appendingPathComponent("outside.json")
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
    try Data("outside".utf8).write(to: outside)
    let policy = home.appendingPathComponent(WorkspaceMutationPolicyStore.fileName)
    try FileManager.default.createSymbolicLink(at: policy, withDestinationURL: outside)

    let store = WorkspaceMutationPolicyStore(harnessHome: home)
    #expect(throws: WorkspaceMutationPolicyError.unsafePolicy) {
        try store.requireCheckpoint()
    }
    #expect(try String(contentsOf: outside, encoding: .utf8) == "outside")

    try FileManager.default.removeItem(at: policy)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: home.path)
    #expect(throws: WorkspaceMutationPolicyError.unsafeHome) {
        try store.requireCheckpoint()
    }
}

@Test func workspaceMutationPolicyRejectsContradictoryOrSharedContent() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FulmarWorkspacePolicyMalformed-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    let policy = root.appendingPathComponent(WorkspaceMutationPolicyStore.fileName)
    let store = WorkspaceMutationPolicyStore(harnessHome: root)

    try Data(#"{"mode":"readWrite","reason":"recoverabilityLimit","schemaVersion":1}"#.utf8)
        .write(to: policy)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: policy.path)
    #expect(throws: WorkspaceMutationPolicyError.unsafePolicy) {
        _ = try store.load()
    }

    try Data(#"{"mode":"readOnly","reason":"checkpointRequired","schemaVersion":1}"#.utf8)
        .write(to: policy, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: policy.path)
    #expect(throws: WorkspaceMutationPolicyError.unsafePolicy) {
        _ = try store.load()
    }
}
