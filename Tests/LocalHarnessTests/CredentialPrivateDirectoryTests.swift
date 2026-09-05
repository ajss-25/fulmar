import Darwin
import Foundation
@testable import LocalHarnessCredentialSecurity
import Testing

private struct CredentialPrivateDirectoryFixture {
    let home: URL

    init(_ label: String) throws {
        home = FileManager.default.temporaryDirectory
            .appendingPathComponent("fulmar-private-home-\(label)-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(home.path, 0o700) == 0 else {
            throw CredentialPrivateDirectoryError.creationFailed
        }
    }

    func remove() { try? FileManager.default.removeItem(at: home) }
}

struct CredentialPrivateDirectoryTests {
    @Test func descriptorWalkCreatesAndRetainsExactPrivateMetadataDirectory() throws {
        let fixture = try CredentialPrivateDirectoryFixture("create")
        defer { fixture.remove() }
        let capability = try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(
            home: fixture.home,
            productName: "Fulmar Test",
            metadataName: "CredentialMetadata"
        )
        let descriptor = try capability.duplicateDescriptor()
        defer { _ = close(descriptor) }
        var metadata = stat()
        var named = stat()
        #expect(fstat(descriptor, &metadata) == 0)
        #expect(lstat(capability.url.path, &named) == 0)
        #expect(metadata.st_dev == named.st_dev)
        #expect(metadata.st_ino == named.st_ino)
        #expect(metadata.st_mode & 0o777 == 0o700)
        // Ancestors need only search handles; the retained final capability
        // must still support the actual metadata store's read/write operations.
        #expect(fcntl(descriptor, F_GETFL) & O_ACCMODE == O_RDONLY)
        #expect(fcntl(descriptor, F_GETFL) & O_EXEC == 0)
        let store = try CredentialFileStateStore(directoryCapability: capability)
        try store.writeMetadata(account: "ref:SEARCH_ONLY_ANCESTORS", kind: "reference")
        #expect(try store.readMetadata(account: "ref:SEARCH_ONLY_ANCESTORS")?.kind == "reference")
    }

    @Test func everyIntermediateSymlinkAndWritableComponentIsRejected() throws {
        let symlinkFixture = try CredentialPrivateDirectoryFixture("symlink")
        defer { symlinkFixture.remove() }
        let target = symlinkFixture.home.appendingPathComponent("RealLibrary", isDirectory: true)
        #expect(mkdir(target.path, 0o700) == 0)
        try FileManager.default.createSymbolicLink(
            at: symlinkFixture.home.appendingPathComponent("Library", isDirectory: true),
            withDestinationURL: target
        )
        #expect(throws: CredentialPrivateDirectoryError.unsafePath) {
            _ = try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(
                home: symlinkFixture.home,
                productName: "Fulmar Test"
            )
        }

        let writableFixture = try CredentialPrivateDirectoryFixture("writable")
        defer { writableFixture.remove() }
        let library = writableFixture.home.appendingPathComponent("Library", isDirectory: true)
        let support = library.appendingPathComponent("Application Support", isDirectory: true)
        #expect(mkdir(library.path, 0o700) == 0)
        #expect(mkdir(support.path, 0o777) == 0)
        #expect(chmod(support.path, 0o777) == 0)
        #expect(throws: CredentialPrivateDirectoryError.unsafePath) {
            _ = try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(
                home: writableFixture.home,
                productName: "Fulmar Test"
            )
        }
    }

    @Test func retainedCapabilityMakesMetadataStoresRejectParentSwap() throws {
        let fixture = try CredentialPrivateDirectoryFixture("swap")
        defer { fixture.remove() }
        let capability = try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(
            home: fixture.home,
            productName: "Fulmar Test"
        )
        let state = try CredentialFileStateStore(directoryCapability: capability)
        let receipt = try CredentialMigrationReceiptStore(
            directoryCapability: capability,
            authenticationKey: Data(repeating: 0x2a, count: 32)
        )
        let moved = capability.url.appendingPathExtension("moved")
        #expect(rename(capability.url.path, moved.path) == 0)
        #expect(mkdir(capability.url.path, 0o700) == 0)

        #expect(throws: CredentialTransactionError.self) {
            try state.writeMetadata(account: "ref:SWAPPED_PARENT", kind: "reference")
        }
        #expect(throws: CredentialMigrationReceiptError.unsafeDirectory) {
            _ = try receipt.read()
        }
    }
}
