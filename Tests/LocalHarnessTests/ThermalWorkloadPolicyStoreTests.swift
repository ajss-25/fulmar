import Darwin
import Foundation
import Testing
@testable import LocalHarness

@Suite("Adaptive thermal workload policy store")
struct ThermalWorkloadPolicyStoreTests {
    private func withSupport(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("FulmarThermalPolicyTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }

    @Test("Preparation creates an exact private normal policy")
    func prepareCreatesPrivatePolicy() throws {
        try withSupport { support in
            let file = try ThermalWorkloadPolicyStore.prepare(applicationSupport: support)
            #expect(file == ThermalWorkloadPolicyStore.storageURL(applicationSupport: support))
            #expect(try ThermalWorkloadPolicyStore.read(applicationSupport: support) == .production(.normal))
            var metadata = stat()
            #expect(Darwin.lstat(file.path, &metadata) == 0)
            #expect(metadata.st_mode & S_IFMT == S_IFREG)
            #expect(metadata.st_mode & 0o777 == 0o600)
            #expect(metadata.st_nlink == 1)
        }
    }

    @Test("Mode changes are atomic, bounded, and reversible")
    func modeChangesRoundTrip() throws {
        try withSupport { support in
            try ThermalWorkloadPolicyStore.setMode(.eco, applicationSupport: support)
            #expect(try ThermalWorkloadPolicyStore.read(applicationSupport: support) == .production(.eco))
            try ThermalWorkloadPolicyStore.setMode(.normal, applicationSupport: support)
            #expect(try ThermalWorkloadPolicyStore.read(applicationSupport: support) == .production(.normal))
            let directory = ThermalWorkloadPolicyStore.storageURL(applicationSupport: support)
                .deletingLastPathComponent()
            let leftovers = try FileManager.default.contentsOfDirectory(atPath: directory.path)
                .filter { $0.hasPrefix(".\(ThermalWorkloadPolicyStore.fileName).") }
            #expect(leftovers.isEmpty)
        }
    }

    @Test("Malformed or permissive policy files fail closed")
    func malformedPolicyFailsClosed() throws {
        try withSupport { support in
            let file = try ThermalWorkloadPolicyStore.prepare(applicationSupport: support)
            try Data(#"{"schemaVersion":1,"mode":"eco"}"#.utf8).write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            #expect(throws: ThermalWorkloadPolicyStoreError.unsafeStorage) {
                try ThermalWorkloadPolicyStore.read(applicationSupport: support)
            }

            try Data(#"{"ecoMaxOutputTokens":2048,"minimumDelayMilliseconds":5000,"mode":"eco","schemaVersion":1}"#.utf8).write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
            #expect(throws: ThermalWorkloadPolicyStoreError.unsafeStorage) {
                try ThermalWorkloadPolicyStore.read(applicationSupport: support)
            }
        }
    }

    @Test("A linked policy target is never followed or replaced")
    func linkedPolicyIsRejected() throws {
        try withSupport { support in
            _ = try GenerationTelemetrySpool.prepare(applicationSupport: support)
            let outside = support.appendingPathComponent("outside")
            try Data("unchanged".utf8).write(to: outside)
            let file = ThermalWorkloadPolicyStore.storageURL(applicationSupport: support)
            try FileManager.default.createSymbolicLink(at: file, withDestinationURL: outside)
            #expect(throws: ThermalWorkloadPolicyStoreError.unsafeStorage) {
                try ThermalWorkloadPolicyStore.prepare(applicationSupport: support)
            }
            #expect(try String(contentsOf: outside, encoding: .utf8) == "unchanged")
        }
    }
}
