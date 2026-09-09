import Foundation
import Darwin
import Testing
@testable import LocalHarness

private struct MCPBundleFixture {
    let root: URL
    let resources: URL
    let guarded: URL
    let clientBridge: URL
    let runtimeManifest: URL

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        resources = root.appendingPathComponent("Resources", isDirectory: true)
        guarded = resources.appendingPathComponent(
            "Runtime/dsh/node_modules/@local-harness/dsh-mcp-guarded",
            isDirectory: true
        )
        clientBridge = resources.appendingPathComponent(
            "Runtime/dsh/node_modules/@local-harness/dsh-client-security-bridge",
            isDirectory: true
        )
        let upstream = resources.appendingPathComponent(
            "Runtime/dsh/node_modules/@deepseek-ai/dsh-mcp-client",
            isDirectory: true
        )
        let upstreamCredentials = resources.appendingPathComponent(
            "Runtime/dsh/node_modules/@deepseek-ai/dsh-credentials",
            isDirectory: true
        )
        let upstreamSchemastery = resources.appendingPathComponent(
            "Runtime/dsh/node_modules/@deepseek-ai/schemastery",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: guarded, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: clientBridge, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: upstream, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: upstreamCredentials, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: upstreamSchemastery, withIntermediateDirectories: true)
        let runtime = resources.appendingPathComponent("Runtime/dsh", isDirectory: true)
        runtimeManifest = runtime.appendingPathComponent("package.json")
        try Data(#"{"name":"@deepseek-ai/dsh","version":"0.1.1-rc.1","dependencies":{"@local-harness/dsh-client-security-bridge":"1.2.1","@local-harness/dsh-credentials-keychain":"1.0.8","@local-harness/dsh-fs-confined":"1.0.0","@local-harness/dsh-mcp-guarded":"1.0.0","@local-harness/dsh-performance-profile":"1.2.0","@local-harness/dsh-web-fetch-safe":"1.0.0"}}"#.utf8)
            .write(to: runtimeManifest)
        try Data(#"{"name":"@deepseek-ai/dsh-mcp-client","version":"0.1.1-rc.1","type":"module","main":"lib/index.js","exports":{".":{"types":"./lib/types/index.d.ts","default":"./lib/index.js"}}}"#.utf8)
            .write(to: upstream.appendingPathComponent("package.json"))
        try Data(#"{"name":"@deepseek-ai/dsh-credentials","version":"0.1.1-rc.1"}"#.utf8)
            .write(to: upstreamCredentials.appendingPathComponent("package.json"))
        try Data(#"{"name":"@deepseek-ai/schemastery","version":"3.18.1"}"#.utf8)
            .write(to: upstreamSchemastery.appendingPathComponent("package.json"))
        try Data(#"{"name":"@local-harness/dsh-mcp-guarded","version":"1.0.0","private":true,"type":"module","main":"./index.mjs","exports":"./index.mjs","peerDependencies":{"@deepseek-ai/dsh-credentials":"0.1.1-rc.1","@deepseek-ai/dsh-mcp-client":"0.1.1-rc.1","@deepseek-ai/schemastery":"3.18.1"}}"#.utf8)
            .write(to: guarded.appendingPathComponent("package.json"))
        for name in MCPBundleSecurityPolicy.guardedPackageFiles where name != "package.json" {
            try Data("export {};\n".utf8).write(to: guarded.appendingPathComponent(name))
        }
        try Data(#"{"name":"@local-harness/dsh-client-security-bridge","version":"1.2.1","private":true,"type":"module","main":"./index.mjs","exports":{".":"./index.mjs","./client":"./client.js","./package.json":"./package.json"},"peerDependencies":{"@deepseek-ai/dsh-host-apiproxy":"0.1.1-rc.1","@deepseek-ai/dsh-llm":"0.1.1-rc.1"},"dsh":{"client":{"inject":["@deepseek-ai/dsh-client-runtime","@deepseek-ai/dsh-client-ui-conversation"],"platform":"web"}}}"#.utf8)
            .write(to: clientBridge.appendingPathComponent("package.json"))
        for name in MCPBundleSecurityPolicy.clientBridgePackageFiles where name != "package.json" {
            try Data("export {};\n".utf8).write(to: clientBridge.appendingPathComponent(name))
        }
        try Data("""
        - insert:
            - id: mcp-guarded
              name: '@local-harness/dsh-mcp-guarded'
              config:
                catalogPath: !!js process.env.LOCAL_HARNESS_MCP_CATALOG
        - insert:
            - id: client-security-bridge
              name: '@local-harness/dsh-client-security-bridge'
        - insert:
            - id: web-fetch-safe
              name: '@local-harness/dsh-web-fetch-safe'
        """.utf8).write(to: resources.appendingPathComponent("LocalHarness.patch.yml"))
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@Test func mcpBundlePolicyAcceptsExactPinnedPackageShape() throws {
    let fixture = try MCPBundleFixture()
    defer { fixture.cleanup() }
    #expect(MCPBundleSecurityPolicy.validate(resources: fixture.resources))
}

@Test func mcpBundlePolicyRejectsRunnerSymlinkAndUnexpectedPackageFiles() throws {
    let fixture = try MCPBundleFixture()
    defer { fixture.cleanup() }
    let runner = fixture.guarded.appendingPathComponent("stdio-guard-runner.mjs")
    let outside = fixture.root.appendingPathComponent("replacement.mjs")
    try Data("export {};\n".utf8).write(to: outside)
    try FileManager.default.removeItem(at: runner)
    try FileManager.default.createSymbolicLink(at: runner, withDestinationURL: outside)
    #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))

    try FileManager.default.removeItem(at: runner)
    try Data("export {};\n".utf8).write(to: runner)
    try Data("unexpected\n".utf8).write(to: fixture.guarded.appendingPathComponent("extra.txt"))
    #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
}

@Test func mcpBundlePolicyBoundsWideDirectoriesAndEveryParsedFile() throws {
    do {
        let fixture = try MCPBundleFixture()
        defer { fixture.cleanup() }
        for index in 0..<256 {
            try Data().write(to: fixture.guarded.appendingPathComponent("unexpected-\(index)"))
        }
        #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
    }

    do {
        let fixture = try MCPBundleFixture()
        defer { fixture.cleanup() }
        try Data(repeating: 0x20, count: MCPBundleSecurityPolicy.maximumPackageJSONBytes + 1)
            .write(to: fixture.runtimeManifest)
        #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
    }

    do {
        let fixture = try MCPBundleFixture()
        defer { fixture.cleanup() }
        try Data(repeating: 0x20, count: MCPBundleSecurityPolicy.maximumPatchBytes + 1)
            .write(to: fixture.resources.appendingPathComponent("LocalHarness.patch.yml"))
        #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
    }

    do {
        let fixture = try MCPBundleFixture()
        defer { fixture.cleanup() }
        let patch = fixture.resources.appendingPathComponent("LocalHarness.patch.yml")
        try FileManager.default.removeItem(at: patch)
        #expect(Darwin.mkfifo(patch.path, 0o600) == 0)
        #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
    }
}

@Test func mcpBundlePolicyRejectsAlteredClientSecurityBridge() throws {
    let fixture = try MCPBundleFixture()
    defer { fixture.cleanup() }
    let client = fixture.clientBridge.appendingPathComponent("client.js")
    let outside = fixture.root.appendingPathComponent("replacement-client.js")
    try Data("export {};\n".utf8).write(to: outside)
    try FileManager.default.removeItem(at: client)
    try FileManager.default.createSymbolicLink(at: client, withDestinationURL: outside)
    #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
}

@Test func mcpBundlePolicyRejectsUnsupportedExpressionPluginNames() throws {
    let fixture = try MCPBundleFixture()
    defer { fixture.cleanup() }
    let patch = fixture.resources.appendingPathComponent("LocalHarness.patch.yml")
    var text = try String(contentsOf: patch, encoding: .utf8)
    text = text.replacingOccurrences(
        of: "'@local-harness/dsh-mcp-guarded'",
        with: "!!js process.env.LOCAL_HARNESS_MCP_PLUGIN"
    )
    try Data(text.utf8).write(to: patch)
    #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
}

@Test func mcpBundlePolicyRejectsMissingAlteredOrUnknownLocalDependencyClosure() throws {
    for dependencies in [
        [
            "@local-harness/dsh-client-security-bridge": "1.2.1",
            "@local-harness/dsh-credentials-keychain": "1.0.8",
            "@local-harness/dsh-fs-confined": "1.0.0",
            "@local-harness/dsh-mcp-guarded": "1.0.0",
            "@local-harness/dsh-web-fetch-safe": "1.0.0"
        ],
        [
            "@local-harness/dsh-client-security-bridge": "1.2.1",
            "@local-harness/dsh-credentials-keychain": "1.0.8",
            "@local-harness/dsh-fs-confined": "1.0.0",
            "@local-harness/dsh-mcp-guarded": "9.9.9",
            "@local-harness/dsh-performance-profile": "1.2.0",
            "@local-harness/dsh-web-fetch-safe": "1.0.0"
        ],
        [
            "@local-harness/dsh-client-security-bridge": "1.2.1",
            "@local-harness/dsh-credentials-keychain": "1.0.8",
            "@local-harness/dsh-fs-confined": "1.0.0",
            "@local-harness/dsh-mcp-guarded": "1.0.0",
            "@local-harness/dsh-performance-profile": "1.2.0",
            "@local-harness/dsh-web-fetch-safe": "1.0.0",
            "@local-harness/unreviewed": "1.0.0"
        ]
    ] {
        let fixture = try MCPBundleFixture()
        defer { fixture.cleanup() }
        let manifest: [String: Any] = [
            "name": "@deepseek-ai/dsh",
            "version": "0.1.1-rc.1",
            "dependencies": dependencies
        ]
        try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
            .write(to: fixture.runtimeManifest)
        #expect(!MCPBundleSecurityPolicy.validate(resources: fixture.resources))
    }
}
