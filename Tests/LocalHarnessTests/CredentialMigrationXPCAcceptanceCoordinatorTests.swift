import Darwin
import Foundation
import LocalHarnessCredentialMigrationXPCProtocol
import Testing
@testable import LocalHarness

struct CredentialMigrationXPCAcceptanceCoordinatorTests {
    @Test func fixtureIsPrivateEmptyUUIDBoundAndRemovedAfterSuccess() throws {
        var capturedRoot: URL?
        try CredentialMigrationXPCAcceptanceCoordinator.exercise { source, lease, nonce in
            let root = source.deletingLastPathComponent()
            capturedRoot = root
            #expect(source.lastPathComponent
                == CredentialMigrationXPCConstants.acceptanceSourceName)
            #expect(root.path == "/private/tmp/"
                + CredentialMigrationXPCConstants.acceptanceDirectoryPrefix + nonce)
            #expect(UUID(uuidString: nonce)?.uuidString.lowercased() == nonce)
            let acceptanceSourceData = try Data(contentsOf: source)
            #expect(acceptanceSourceData.isEmpty)

            var rootMetadata = stat()
            var sourceMetadata = stat()
            var leaseMetadata = stat()
            #expect(lstat(root.path, &rootMetadata) == 0)
            #expect(lstat(source.path, &sourceMetadata) == 0)
            #expect(fstat(lease.sourceDescriptor, &leaseMetadata) == 0)
            #expect(rootMetadata.st_mode & 0o777 == 0o700)
            #expect(sourceMetadata.st_mode & 0o777 == 0o600)
            #expect(sourceMetadata.st_size == 0)
            #expect(leaseMetadata.st_mode & 0o777 == 0o600)
            #expect(leaseMetadata.st_size == 0)
            #expect(UInt64(truncatingIfNeeded: leaseMetadata.st_dev) == lease.expectedDevice)
            #expect(UInt64(leaseMetadata.st_ino) == lease.expectedInode)

            // Exercise the real client-side guard on the now-existing private
            // fixture, not merely the injected successful response below.
            #expect(CredentialMigrationXPCClient.isCanonicalFileURL(source))
            #expect(CredentialMigrationXPCClient.isCanonicalFileURL(root))
            #expect(CredentialMigrationXPCClient.validateCommittedPaths(
                sourceURL: source,
                leaseDescriptor: lease,
                expectedSourceDevice: UInt64(truncatingIfNeeded: sourceMetadata.st_dev),
                expectedSourceInode: UInt64(sourceMetadata.st_ino),
                expectedSourceName: CredentialMigrationXPCConstants.acceptanceSourceName
            ))
            let capabilities = try CredentialMigrationXPCClient.makeCapabilities(
                sourceURL: source,
                leaseDescriptor: lease,
                deadline: 5,
                operation: .acceptance,
                acceptanceNonce: nonce
            )
            defer {
                try? capabilities.source.close()
                try? capabilities.parent.close()
                try? capabilities.lease.close()
            }
            #expect(capabilities.request.source.device == UInt64(truncatingIfNeeded: sourceMetadata.st_dev))
            #expect(capabilities.request.source.inode == UInt64(sourceMetadata.st_ino))
            #expect(capabilities.request.lease.device == lease.expectedDevice)
            #expect(capabilities.request.lease.inode == lease.expectedInode)
            let aliasRoot = URL(fileURLWithPath: root.path + "-alias", isDirectory: true)
            try FileManager.default.createSymbolicLink(at: aliasRoot, withDestinationURL: root)
            defer { try? FileManager.default.removeItem(at: aliasRoot) }
            let rejectedSources = [
                URL(fileURLWithPath: String(source.path.dropFirst("/private".count))),
                URL(fileURLWithPath: root.path + "/./" + source.lastPathComponent),
                URL(fileURLWithPath: root.path + "/../" + root.lastPathComponent + "/" + source.lastPathComponent),
                aliasRoot.appendingPathComponent(source.lastPathComponent),
            ]
            for rejected in rejectedSources {
                #expect(!CredentialMigrationXPCClient.isCanonicalFileURL(rejected))
                #expect(!CredentialMigrationXPCClient.validateCommittedPaths(
                    sourceURL: rejected,
                    leaseDescriptor: lease,
                    expectedSourceName: CredentialMigrationXPCConstants.acceptanceSourceName
                ))
                #expect(throws: CredentialMigrationXPCClientError.invalidCapabilities) {
                    let rejectedCapabilities = try CredentialMigrationXPCClient.makeCapabilities(
                        sourceURL: rejected,
                        leaseDescriptor: lease,
                        deadline: 5,
                        operation: .acceptance,
                        acceptanceNonce: nonce
                    )
                    try rejectedCapabilities.source.close()
                    try rejectedCapabilities.parent.close()
                    try rejectedCapabilities.lease.close()
                }
            }
            return CredentialMigrationXPCResponse(status: .success)
        }
        let root = try #require(capturedRoot)
        var removed = stat()
        #expect(lstat(root.path, &removed) != 0)
        #expect(errno == ENOENT)
    }

    @Test func invalidReplyStillRemovesTheBoundFixture() throws {
        var capturedRoot: URL?
        #expect(throws: CredentialMigrationXPCAcceptanceError.invalidResponse) {
            try CredentialMigrationXPCAcceptanceCoordinator.exercise { source, _, _ in
                capturedRoot = source.deletingLastPathComponent()
                return CredentialMigrationXPCResponse(status: .success, references: 1)
            }
        }
        let root = try #require(capturedRoot)
        var removed = stat()
        #expect(lstat(root.path, &removed) != 0)
        #expect(errno == ENOENT)
    }
}
