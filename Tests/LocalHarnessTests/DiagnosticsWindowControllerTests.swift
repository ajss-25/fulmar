import Foundation
import Testing
@testable import LocalHarness

@Test
func diagnosticsConfiguredModelUsesABoundedNoFollowRead() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("diagnostics-settings-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let settings = root.appendingPathComponent("settings.yaml")
    try Data("provider: ollama\nmodel: qwen3.8:27b-mlx\n".utf8).write(to: settings)
    #expect(DiagnosticsWindowController.configuredModel(at: settings) == "qwen3.8:27b-mlx")

    try Data(repeating: 0x41, count: DiagnosticsWindowController.maximumSettingsBytes + 1)
        .write(to: settings, options: .atomic)
    #expect(DiagnosticsWindowController.configuredModel(at: settings) == "Unknown")

    let outside = root.appendingPathComponent("outside.yaml")
    try Data("model: should-not-follow\n".utf8).write(to: outside)
    try FileManager.default.removeItem(at: settings)
    try FileManager.default.createSymbolicLink(at: settings, withDestinationURL: outside)
    #expect(DiagnosticsWindowController.configuredModel(at: settings) == "Unknown")
}

@Test
func copiedDiagnosticsReportRemovesAbsoluteHomeAndRuntimeExecutablePaths() {
    let home = URL(fileURLWithPath: "/Users/private-person", isDirectory: true)
    let node = URL(fileURLWithPath: "/Applications/Fulmar.app/Contents/Resources/Runtime/node")
    let entry = URL(fileURLWithPath: "/Applications/Fulmar.app/Contents/Resources/Runtime/dsh/dist/index.js")
    let raw = """
    Workspace failure at /Users/private-person/Library/Application Support/Local Harness/Workspace
    node=/Applications/Fulmar.app/Contents/Resources/Runtime/node
    entry=/Applications/Fulmar.app/Contents/Resources/Runtime/dsh/dist/index.js
    """

    let copied = DiagnosticsWindowController.shareableSupportReport(
        raw,
        homeDirectory: home,
        runtimeExecutablePaths: [node, entry]
    )

    #expect(!copied.contains(home.path))
    #expect(!copied.contains(node.path))
    #expect(!copied.contains(entry.path))
    #expect(copied.contains("<private home>"))
    #expect(copied.components(separatedBy: "<runtime path removed>").count == 3)
}

@Test
func diagnosticsCopyBoundaryIsIdempotentAndReappliesSecretSanitization() throws {
    let source = try String(contentsOf: URL(
        fileURLWithPath: #filePath
    ).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/LocalHarness/DiagnosticsWindowController.swift"), encoding: .utf8)
    let home = URL(fileURLWithPath: "/Users/private-person", isDirectory: true)
    let assembled: ([String]) -> String = { $0.joined() }
    let secrets = [
        assembled(["eyJhbGciOiJ", "IUzI1NiJ9.", "eyJzdWIiOiI", "xMjM0NTY3ODkwIn0.", "signature12345"]),
        assembled(["AK", "IAABCDEFGHIJKLMNOP"]),
        assembled(["gh", "p_abcdefghijklmnopqrstuvwxyz123456"]),
        assembled(["xo", "xb-1234567890-abcdefghijklmnop"]),
        assembled(["h", "f_abcdefghijklmnopqrstuvwxyz123456"]),
        assembled(["AI", "zaABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"]),
        assembled(["s", "k-abcdefghijklmnopqrstuvwxyz"]),
        assembled(["r", "k_abcdefghijklmnopqrstuvwxyz"]),
        assembled(["a", "pi-abcdefghijklmnopqrstuvwxyz"])
    ]
    let privateKeyBody = assembled(["MIIEvQI", "BADANBgkqhkiG9w0BA-private-material"])
    let privateKeyBlock = [
        assembled(["-----BEGIN", " PRIVATE KEY-----"]),
        privateKeyBody,
        assembled(["-----END", " PRIVATE KEY-----"])
    ].joined(separator: "\n")
    let raw = """
    /Users/private-person/private.txt
    \(secrets.joined(separator: "\n"))
    \(privateKeyBlock)
    """
    let once = DiagnosticsWindowController.shareableSupportReport(
        raw,
        homeDirectory: home,
        runtimeExecutablePaths: []
    )
    let twice = DiagnosticsWindowController.shareableSupportReport(
        once,
        homeDirectory: home,
        runtimeExecutablePaths: []
    )

    #expect(once == twice)
    for secret in secrets {
        #expect(!once.contains(secret))
    }
    #expect(!once.contains(privateKeyBody))
    #expect(once.contains("[REDACTED PRIVATE KEY]"))
    #expect(once.contains("[REDACTED JWT]"))
    #expect(source.contains("KNOWN CREDENTIAL PATTERNS REDACTED"))
    #expect(source.contains("Known credential patterns and private paths are redacted again"))
    #expect(!source.contains("SANITIZED RECENT SERVICE LOG"))
}
