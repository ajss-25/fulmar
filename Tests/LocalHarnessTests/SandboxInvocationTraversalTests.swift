import Darwin
import Foundation
import Testing
@testable import LocalHarnessSandboxPolicy

private struct SandboxTraversalFixture {
    let root: URL
    let workspace: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .resolvingSymlinksInPath()
            .appendingPathComponent("sandbox-traversal-\(UUID().uuidString)", isDirectory: true)
        workspace = root.appendingPathComponent("workspace", isDirectory: true)
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func capturedWorkspaceScanLimit(
    _ operation: () throws -> Void
) -> LocalHarnessWorkspaceScanLimit? {
    do {
        try operation()
        Issue.record("Expected the bounded workspace scan to fail closed")
        return nil
    } catch LocalHarnessSandboxError.workspaceScanLimitExceeded(let limit) {
        return limit
    } catch {
        Issue.record("Expected a typed workspace scan limit, received \(error)")
        return nil
    }
}

@Test func sandboxWorkspaceTraversalRejectsWideTreesAtTheExactEntryLimit() throws {
    let fixture = try SandboxTraversalFixture()
    defer { fixture.remove() }
    for index in 0..<4 {
        try Data().write(to: fixture.workspace.appendingPathComponent("entry-\(index)"))
    }
    var limits = LocalHarnessWorkspaceScanLimits()
    limits.maximumEntries = 3

    let observed = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: fixture.workspace,
            limits: limits
        )
    }
    #expect(observed == .entryCount(maximum: 3))
}

@Test func sandboxWorkspaceTraversalRejectsDeepTreesBeforeOpeningPastTheLimit() throws {
    let fixture = try SandboxTraversalFixture()
    defer { fixture.remove() }
    let first = fixture.workspace.appendingPathComponent("first", isDirectory: true)
    let second = first.appendingPathComponent("second", isDirectory: true)
    let third = second.appendingPathComponent("third", isDirectory: true)
    try FileManager.default.createDirectory(at: third, withIntermediateDirectories: true)
    var limits = LocalHarnessWorkspaceScanLimits()
    limits.maximumDepth = 2

    let observed = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: fixture.workspace,
            limits: limits
        )
    }
    #expect(observed == .depth(maximum: 2))
}

@Test func sandboxWorkspaceTraversalEnforcesNamePathAndAggregateUTF8Budgets() throws {
    let nameFixture = try SandboxTraversalFixture()
    defer { nameFixture.remove() }
    try Data().write(to: nameFixture.workspace.appendingPathComponent("four"))
    var nameLimits = LocalHarnessWorkspaceScanLimits()
    nameLimits.maximumNameBytes = 3
    let nameObserved = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: nameFixture.workspace,
            limits: nameLimits
        )
    }
    #expect(nameObserved == .nameBytes(maximum: 3))

    let pathFixture = try SandboxTraversalFixture()
    defer { pathFixture.remove() }
    try Data().write(to: pathFixture.workspace.appendingPathComponent("path-too-long"))
    let pathMaximum = pathFixture.workspace.path.utf8.count + 2
    var pathLimits = LocalHarnessWorkspaceScanLimits()
    pathLimits.maximumPathBytes = pathMaximum
    let pathObserved = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: pathFixture.workspace,
            limits: pathLimits
        )
    }
    #expect(pathObserved == .pathBytes(maximum: pathMaximum))

    let aggregateFixture = try SandboxTraversalFixture()
    defer { aggregateFixture.remove() }
    try Data().write(to: aggregateFixture.workspace.appendingPathComponent("a"))
    try Data().write(to: aggregateFixture.workspace.appendingPathComponent("b"))
    let onePathBytes = aggregateFixture.workspace.appendingPathComponent("a").path.utf8.count
    var aggregateLimits = LocalHarnessWorkspaceScanLimits()
    aggregateLimits.maximumPathBytes = onePathBytes
    aggregateLimits.maximumAggregatePathBytes = onePathBytes
    let aggregateObserved = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: aggregateFixture.workspace,
            limits: aggregateLimits
        )
    }
    #expect(aggregateObserved == .aggregatePathBytes(maximum: onePathBytes))
}

@Test func sandboxWorkspaceTraversalUsesOneInjectedMonotonicDeadline() throws {
    let fixture = try SandboxTraversalFixture()
    defer { fixture.remove() }
    try Data().write(to: fixture.workspace.appendingPathComponent("entry"))
    var limits = LocalHarnessWorkspaceScanLimits()
    limits.maximumDurationNanoseconds = 1
    var tick: UInt64 = 0

    let observed = capturedWorkspaceScanLimit {
        _ = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(
            in: fixture.workspace,
            limits: limits,
            monotonicNow: {
                defer { tick += 2 }
                return tick
            }
        )
    }
    #expect(observed == .deadline)
}

@Test func sandboxWorkspaceTraversalFindsNestedHardLinksAndDoesNotFollowSymlinks() throws {
    let fixture = try SandboxTraversalFixture()
    defer { fixture.remove() }
    let outside = fixture.root.appendingPathComponent("outside", isDirectory: true)
    let nested = fixture.workspace.appendingPathComponent("nested", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

    let source = outside.appendingPathComponent("source.txt")
    let alias = nested.appendingPathComponent("alias.txt")
    try Data("protected".utf8).write(to: source)
    try FileManager.default.linkItem(at: source, to: alias)
    let linkedOutsideDirectory = outside.appendingPathComponent("linked-directory", isDirectory: true)
    try FileManager.default.createDirectory(at: linkedOutsideDirectory, withIntermediateDirectories: true)
    let escapedSource = linkedOutsideDirectory.appendingPathComponent("escaped-source.txt")
    let escapedAlias = outside.appendingPathComponent("escaped-alias.txt")
    try Data("outside".utf8).write(to: escapedSource)
    try FileManager.default.linkItem(at: escapedSource, to: escapedAlias)
    try FileManager.default.createSymbolicLink(
        at: fixture.workspace.appendingPathComponent("do-not-follow", isDirectory: true),
        withDestinationURL: linkedOutsideDirectory
    )

    let aliases = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(in: fixture.workspace)
    #expect(aliases == [alias.path])

    let invocation = try LocalHarnessSandboxInvocation(
        arguments: [
            "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-pid", "--proc", "/proc",
            "--die-with-parent", "--tmpfs", "/tmp", "--bind", fixture.workspace.path,
            fixture.workspace.path, "--", "/usr/bin/true"
        ],
        strictLocal: true,
        approvedWorkspaceRoots: [fixture.workspace],
        currentDirectory: fixture.workspace
    )
    #expect(invocation.profile.contains("(deny file-write* (literal \"\(alias.path)\"))"))
    #expect(!invocation.profile.contains(escapedSource.path))
}

@Test func sandboxWorkspaceTraversalAcceptsDarwinMaximumFilename() throws {
    let fixture = try SandboxTraversalFixture()
    defer { fixture.remove() }
    let name = String(repeating: "x", count: Int(MAXNAMLEN))
    try Data().write(to: fixture.workspace.appendingPathComponent(name))

    let aliases = try LocalHarnessSandboxInvocation.hardLinkedRegularFiles(in: fixture.workspace)
    #expect(aliases.isEmpty)
}
