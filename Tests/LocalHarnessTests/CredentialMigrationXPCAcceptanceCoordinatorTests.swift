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
