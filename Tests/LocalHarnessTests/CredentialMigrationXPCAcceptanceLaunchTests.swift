import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol
import Testing
@testable import LocalHarness

struct CredentialMigrationXPCAcceptanceLaunchTests {
    private func packagedExecutable(_ root: URL) throws -> URL {
        let executable = root
            .appendingPathComponent("Fulmar.app/Contents/MacOS/LocalHarness", isDirectory: false)
        try FileManager.default.createDirectory(
            at: executable.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try Data().write(to: executable, options: .withoutOverwriting)
        return executable
    }

    @Test func exactRequestResolvesOnlySiblingPackagedCapabilities() throws {
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-xpc-launch-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = try packagedExecutable(root)
        let result = try #require(
            try CredentialMigrationXPCAcceptanceLaunch.configurationIfRequested(
                arguments: [
                    executable.path,
                    CredentialMigrationXPCAcceptanceCoordinator.launchArgument,
                ],
                executableURL: executable
            )
        )
        #expect(result.helperURL.path
            == root.appendingPathComponent(
                "Fulmar.app/Contents/MacOS/LocalHarnessCredentialHelper"
            ).path)
        #expect(result.serviceBundleURL.path
            == root.appendingPathComponent(
                "Fulmar.app/Contents/XPCServices/"
                    + CredentialMigrationXPCConstants.serviceBundleName
            ).path)
    }

    @Test func absentArgumentDoesNothingAndWritesNothing() throws {
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-xpc-launch-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = try packagedExecutable(root)
        let output = Pipe()
        let error = Pipe()
        var invoked = false
        let status = CredentialMigrationXPCAcceptanceLaunch.runIfRequested(
            arguments: [executable.path],
            executableURL: executable,
            standardOutput: output.fileHandleForWriting,
            standardError: error.fileHandleForWriting,
            invocation: { _, _ in invoked = true }
        )
        try output.fileHandleForWriting.close()
        try error.fileHandleForWriting.close()
        #expect(status == nil)
        #expect(!invoked)
        #expect(output.fileHandleForReading.readDataToEndOfFile().isEmpty)
        #expect(error.fileHandleForReading.readDataToEndOfFile().isEmpty)
    }

    @Test func extraReorderedAndPathDriftRequestsFailGenericallyWithoutInvocation() throws {
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-xpc-launch-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = try packagedExecutable(root)
        let argument = CredentialMigrationXPCAcceptanceCoordinator.launchArgument
        let cases = [
            [executable.path, argument, "extra"],
            [executable.path, "extra", argument],
            [executable.path + "-drift", argument],
        ]
        for arguments in cases {
            let output = Pipe()
            let error = Pipe()
            var invoked = false
            let status = CredentialMigrationXPCAcceptanceLaunch.runIfRequested(
                arguments: arguments,
                executableURL: executable,
                standardOutput: output.fileHandleForWriting,
                standardError: error.fileHandleForWriting,
                invocation: { _, _ in invoked = true }
            )
            try output.fileHandleForWriting.close()
            try error.fileHandleForWriting.close()
            #expect(status == EX_CONFIG)
            #expect(!invoked)
            #expect(output.fileHandleForReading.readDataToEndOfFile().isEmpty)
            #expect(String(
                data: error.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) == CredentialMigrationXPCAcceptanceLaunch.genericFailure)
        }
    }

    @Test func successAndFailureHaveExactContentFreeOutputContracts() throws {
        let root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-xpc-launch-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = try packagedExecutable(root)
        let arguments = [
            executable.path,
            CredentialMigrationXPCAcceptanceCoordinator.launchArgument,
        ]
        for shouldFail in [false, true] {
            let output = Pipe()
            let error = Pipe()
            let status = CredentialMigrationXPCAcceptanceLaunch.runIfRequested(
                arguments: arguments,
                executableURL: executable,
                standardOutput: output.fileHandleForWriting,
                standardError: error.fileHandleForWriting,
                invocation: { _, _ in
                    if shouldFail { throw CredentialMigrationXPCAcceptanceError.invalidResponse }
                }
            )
            try output.fileHandleForWriting.close()
            try error.fileHandleForWriting.close()
            let outputData = output.fileHandleForReading.readDataToEndOfFile()
            let errorData = error.fileHandleForReading.readDataToEndOfFile()
            if shouldFail {
                #expect(status == EX_CONFIG)
                #expect(outputData.isEmpty)
                #expect(String(data: errorData, encoding: .utf8)
                    == CredentialMigrationXPCAcceptanceLaunch.genericFailure)
            } else {
                #expect(status == EX_OK)
                #expect(String(data: outputData, encoding: .utf8)
                    == CredentialMigrationXPCAcceptanceLaunch.successSentinel)
                #expect(errorData.isEmpty)
            }
        }
    }
}
