import Darwin
import Foundation
@testable import LocalHarnessCredentialSecurity
import Testing

private struct CredentialReceiptFixture {
    let root: URL
    let key = Data(repeating: 0x5a, count: 32)

    init(_ label: String) throws {
        root = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("fulmar-receipt-\(label)-\(UUID().uuidString)", isDirectory: true)
        guard mkdir(root.path, 0o700) == 0 else {
            throw CredentialMigrationReceiptError.persistenceFailure
        }
    }

    func remove() { try? FileManager.default.removeItem(at: root) }

    func receipt(phase: CredentialMigrationReceiptPhase = .prepared) -> CredentialMigrationReceipt {
        CredentialMigrationReceipt(
            phase: phase,
            sourceDevice: 123,
            sourceInode: 456,
            sourceSize: 789,
            sourceSHA256: String(repeating: "a", count: 64),
            references: 1,
            records: 1,
            entries: [
                CredentialMigrationReceiptEntry(
                    account: "record:two", kind: "api-key", valueSHA256: String(repeating: "b", count: 64)
                ),
                CredentialMigrationReceiptEntry(
                    account: "ref:ONE", kind: "reference", valueSHA256: String(repeating: "c", count: 64)
                ),
            ].sorted { $0.account < $1.account }
        )
    }
}

struct CredentialMigrationReceiptTests {
    @Test func preparedAndScrubbedReceiptsRoundTripWithAuthentication() throws {
        let fixture = try CredentialReceiptFixture("roundtrip")
        defer { fixture.remove() }
        let store = try CredentialMigrationReceiptStore(
            directory: fixture.root,
            authenticationKey: fixture.key
        )
        let prepared = fixture.receipt()
        try store.write(prepared)
        #expect(try store.read() == prepared)
        let scrubbed = prepared.replacingPhase(.scrubbed)
        try store.write(scrubbed)
        #expect(try store.read() == scrubbed)
    }

    @Test func wrongKeyTamperingAndNoncanonicalBytesAreRejected() throws {
        let fixture = try CredentialReceiptFixture("authentication")
        defer { fixture.remove() }
        let store = try CredentialMigrationReceiptStore(
            directory: fixture.root,
            authenticationKey: fixture.key
        )
        try store.write(fixture.receipt())
        let wrongKey = try CredentialMigrationReceiptStore(
            directory: fixture.root,
            authenticationKey: Data(repeating: 0x6b, count: 32)
        )
        #expect(throws: CredentialMigrationReceiptError.invalidReceipt) {
            _ = try wrongKey.read()
        }

        let receiptURL = fixture.root.appendingPathComponent(
            CredentialMigrationReceiptStore.fileName,
            isDirectory: false
        )
        let descriptor = open(receiptURL.path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
        #expect(descriptor >= 0)
        if descriptor >= 0 {
            var newline: UInt8 = 0x0a
            #expect(write(descriptor, &newline, 1) == 1)
            #expect(fsync(descriptor) == 0)
            _ = close(descriptor)
        }
        #expect(throws: CredentialMigrationReceiptError.invalidReceipt) {
            _ = try store.read()
        }
    }

    @Test func linkedReceiptAndDirectoryPathReplacementAreRejected() throws {
        let fixture = try CredentialReceiptFixture("identity")
        defer { fixture.remove() }
        let store = try CredentialMigrationReceiptStore(
            directory: fixture.root,
            authenticationKey: fixture.key
        )
        try store.write(fixture.receipt())
        let receiptURL = fixture.root.appendingPathComponent(
            CredentialMigrationReceiptStore.fileName,
            isDirectory: false
        )
        let alias = fixture.root.appendingPathComponent("receipt-alias", isDirectory: false)
        #expect(link(receiptURL.path, alias.path) == 0)
        #expect(throws: CredentialMigrationReceiptError.invalidReceipt) {
            _ = try store.read()
        }
        #expect(unlink(alias.path) == 0)

        let moved = fixture.root.appendingPathExtension("moved")
        #expect(rename(fixture.root.path, moved.path) == 0)
        #expect(mkdir(fixture.root.path, 0o700) == 0)
        #expect(throws: CredentialMigrationReceiptError.unsafeDirectory) {
            _ = try store.read()
        }
        try? FileManager.default.removeItem(at: fixture.root)
        try? FileManager.default.removeItem(at: moved)
    }

    @Test func receiptRejectsCountDigestOrderingAndAuthenticationKeyErrors() throws {
        let fixture = try CredentialReceiptFixture("schema")
        defer { fixture.remove() }
        #expect(throws: CredentialMigrationReceiptError.invalidAuthenticationKey) {
            _ = try CredentialMigrationReceiptStore(
                directory: fixture.root,
                authenticationKey: Data(repeating: 1, count: 31)
            )
        }
        let store = try CredentialMigrationReceiptStore(
            directory: fixture.root,
            authenticationKey: fixture.key
        )
        let invalid = CredentialMigrationReceipt(
            phase: .prepared,
            sourceDevice: 1,
            sourceInode: 2,
            sourceSize: 3,
            sourceSHA256: "not-a-digest",
            references: 1,
            records: 0,
            entries: []
        )
        #expect(throws: CredentialMigrationReceiptError.invalidReceipt) {
            try store.write(invalid)
        }
    }
}
