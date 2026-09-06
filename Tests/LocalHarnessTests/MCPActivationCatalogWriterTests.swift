import Foundation
import Testing
@testable import LocalHarness

@Suite("MCP activation catalog")
struct MCPActivationCatalogWriterTests {
    @Test("Empty catalogs replace stale bytes atomically and stay owner-only")
    func writesEmptyCatalogPrivately() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("LocalHarness-MCPCatalog-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)

        let first = try MCPActivationCatalogWriter.write(plans: [], applicationSupport: root)
        try Data("stale material".utf8).write(to: first)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: first.path)
        let second = try MCPActivationCatalogWriter.write(plans: [], applicationSupport: root)

        #expect(first == second)
        let decoded = try JSONDecoder().decode(MCPActivationCatalog.self, from: Data(contentsOf: second))
        #expect(decoded == MCPActivationCatalog(plans: []))
        let attributes = try FileManager.default.attributesOfItem(atPath: second.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }

    @Test("A linked or symlinked catalog destination fails closed")
    func rejectsUnsafeDestinations() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("LocalHarness-MCPCatalogUnsafe-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let security = root.appendingPathComponent("Security", isDirectory: true)
        try FileManager.default.createDirectory(at: security, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: security.path)
        let outside = root.appendingPathComponent("outside.json")
        try Data("preserve".utf8).write(to: outside)
        let destination = security.appendingPathComponent(MCPActivationCatalogWriter.filename)
        try FileManager.default.createSymbolicLink(at: destination, withDestinationURL: outside)

        #expect(throws: MCPActivationCatalogError.insecureStorage) {
            _ = try MCPActivationCatalogWriter.write(plans: [], applicationSupport: root)
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "preserve")
    }
}
