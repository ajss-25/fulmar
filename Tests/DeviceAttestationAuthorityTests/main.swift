import CryptoKit
import Darwin
import Foundation
import Security
@_spi(Testing) import LocalHarnessDeviceAttestation

private enum TestFailure: Error { case failed(String) }
private func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw TestFailure.failed(message) }
}
private func expectThrows(_ expected: DeviceAttestationError, _ body: () throws -> Void) throws {
    do { try body(); throw TestFailure.failed("expected \(expected)") }
    catch let actual as DeviceAttestationError {
        guard actual == expected else { throw TestFailure.failed("expected \(expected), got \(actual)") }
    }
}

private final class MemoryKeyStore: DeviceAttestationRecoverableKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    var values: [String: Data]
    var reads: [String] = []
    var inserts: [String] = []
    var deletes: [String] = []
    var failure: DeviceAttestationError?
    var insertFailureAccount: String?
    var deleteFailureAccount: String?
    init(_ values: [String: Data] = [:]) { self.values = values }
    func read(account: String) throws -> Data? {
        try lock.withLock { reads.append(account); if let failure { throw failure }; return values[account] }
    }
    func insert(_ data: Data, account: String) throws {
        try lock.withLock {
            if let failure { throw failure }
            if insertFailureAccount == account { throw DeviceAttestationError.keychainFailure(errSecIO) }
            guard values[account] == nil else { throw DeviceAttestationError.keychainFailure(errSecDuplicateItem) }
            values[account] = data; inserts.append(account)
        }
    }
    func delete(account: String) throws {
        try lock.withLock {
            if let failure { throw failure }
            if deleteFailureAccount == account { throw DeviceAttestationError.keychainFailure(errSecIO) }
            values.removeValue(forKey: account)
            deletes.append(account)
        }
    }
    func resetObservations() { lock.withLock { reads = []; inserts = []; deletes = [] } }
}

private struct Fixture {
    let root: URL
    let configuration: DeviceAttestationAuthority.Configuration
    init() throws {
        // The attestation path deliberately refuses a world-writable ancestor
        // such as /private/tmp. Resolve the account home from the OS identity,
        // not HOME/CFFIXED_USER_HOME supplied by a hostile or isolated runner,
        // and keep the UUID fixture in the owner-private Caches directory.
        guard let account = getpwuid(geteuid()), let homePointer = account.pointee.pw_dir else {
            throw TestFailure.failed("account home unavailable")
        }
        let canonicalTemporary = URL(fileURLWithPath: String(cString: homePointer), isDirectory: true)
            .appendingPathComponent("Library/Caches", isDirectory: true)
        let candidateRoot = canonicalTemporary.appendingPathComponent(
            "fulmar-device-attestation-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try FileManager.default.createDirectory(
                at: candidateRoot,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateRoot.path
            )
        } catch {
            try? FileManager.default.removeItem(at: candidateRoot)
            throw error
        }
        root = candidateRoot
        configuration = .init(controlParent: candidateRoot)
    }
    var control: URL { root.appendingPathComponent(".FulmarControl/DeviceAttestation", isDirectory: true) }
    func privateDirectory(_ name: String) throws -> URL {
        let result = root.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: result.path)
        return result
    }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@main private struct DeviceAttestationAuthorityTests {
    static func main() throws {
        try run("envelope", envelopeSchemaTamperAndDomain)
        try run("background", backgroundAnchorOnly)
        try run("preplant", preplantAndHalfState)
        try run("bootstrap-recovery", explicitBootstrapRecovery)
        try run("path", pathSymlinkModeAndACL)
        try run("publication", preparedRenameCurrentOpaqueRoot)
        try run("crash", everyCrashWindow)
        try run("tamper", markerTamperAndDeadline)
        try run("harness-home", harnessHomeCapabilityTamperSwapAndCrash)
        try run("harness-home-rotation", harnessHomeRotationCrashRecovery)
        print("DeviceAttestationAuthorityTests: 10 passed")
    }

    static func run(_ name: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch { FileHandle.standardError.write(Data("FAILED \(name): \(error)\n".utf8)); throw error }
    }

    static func envelopeSchemaTamperAndDomain() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore())
        let envelope = try authority.sign(payload: Data("receipt".utf8), domain: "test.domain/a")
        try expect(try authority.verifier().verify(envelope, expectedDomain: "test.domain/a") == Data("receipt".utf8), "payload")
        try expectThrows(.wrongDomain) { _ = try authority.verifier().verify(envelope, expectedDomain: "test.domain/b") }
        guard var object = try JSONSerialization.jsonObject(with: envelope.encoded) as? [String: Any] else { throw TestFailure.failed("envelope JSON") }
        object["unexpected"] = true
        let extended = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try expectThrows(.malformedEnvelope) { _ = try authority.verifier().verify(.init(encoded: extended), expectedDomain: "test.domain/a") }
        object.removeValue(forKey: "unexpected"); object["payload"] = Data("tampered".utf8).base64EncodedString()
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try expectThrows(.invalidSignature) { _ = try authority.verifier().verify(.init(encoded: tampered), expectedDomain: "test.domain/a") }
    }

    static func backgroundAnchorOnly() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let keys = MemoryKeyStore()
        try expect(try ProviderHistoryNamespaceMarkerStore.backgroundState(
            namespaceName: "clean", expectedURL: fixture.root.appendingPathComponent("clean"), expectedPrivacyEpoch: 1,
            expectedReceipt: Data(),
            configuration: fixture.configuration, keyStore: keys) == .absent, "clean absent")
        try expect(keys.reads.isEmpty && keys.inserts.isEmpty, "absent background touched Keychain")
        _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        keys.resetObservations(); _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys)
        try expect(keys.reads == [fixture.configuration.publicAnchorAccount], "background queried private key")
        keys.values.removeValue(forKey: fixture.configuration.publicAnchorAccount)
        try expectThrows(.publicAnchorMissing) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        keys.failure = .keychainFailure(errSecInteractionNotAllowed)
        try expectThrows(.keychainFailure(errSecInteractionNotAllowed)) {
            _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys)
        }
    }

    static func preplantAndHalfState() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            try FileManager.default.createDirectory(at: fixture.control, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.root.appendingPathComponent(".FulmarControl").path)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.control.path)
            let file = fixture.control.appendingPathComponent(DeviceAttestationAuthority.publicKeyFileName)
            try Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            let keys = MemoryKeyStore()
            try expectThrows(.untrustedPreexistingPublicKey) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys) }
            try expect(keys.inserts.isEmpty, "preplant mutated Keychain")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let privateKey = Curve25519.Signing.PrivateKey(), wrongAnchor = Data(repeating: 0x5a, count: 32)
            let keys = MemoryKeyStore([fixture.configuration.privateKeyAccount: privateKey.rawRepresentation,
                                       fixture.configuration.publicAnchorAccount: wrongAnchor])
            try expectThrows(.keyMaterialMismatch) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys) }
            try expect(keys.values[fixture.configuration.publicAnchorAccount] == wrongAnchor && keys.inserts.isEmpty, "half-state replaced")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let plantedPrivate = Curve25519.Signing.PrivateKey().rawRepresentation
            let keys = MemoryKeyStore([fixture.configuration.privateKeyAccount: plantedPrivate])
            try expectThrows(.publicAnchorMissing) {
                _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            }
            try expect(keys.inserts.isEmpty, "private-only half-state was completed")
        }
    }

    static func explicitBootstrapRecovery() throws {
        // Simulate power loss after private-key insertion but before the public
        // anchor. Ordinary foreground open remains detection-only. Only an
        // explicit operation beneath DeviceTrustRecovery can reset the two
        // exact accounts and bootstrap a new generation.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            keys.insertFailureAccount = fixture.configuration.publicAnchorAccount
            try expectThrows(.keychainFailure(errSecIO)) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            keys.insertFailureAccount = nil
            try expect(keys.values[fixture.configuration.privateKeyAccount] != nil, "private half not retained")
            try expectThrows(.publicAnchorMissing) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-explicit", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            let state = try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                configuration: fixture.configuration
            )
            let authorization = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                configuration: fixture.configuration,
                recoveryOperationRoot: operation,
                expectedControlState: state
            )
            let repaired = try DeviceAttestationAuthority.recoverForeground(
                configuration: fixture.configuration,
                keyStore: keys,
                authorization: authorization
            )
            try expect(keys.deletes == [
                fixture.configuration.privateKeyAccount,
                fixture.configuration.publicAnchorAccount
            ], "recovery deleted an unexpected Keychain account")
            _ = try repaired.sign(payload: Data("new-generation".utf8), domain: "test.recovered")
            try expect(FileManager.default.fileExists(
                atPath: operation.appendingPathComponent("DeviceAttestationControl").path
            ), "old control namespace was not retained")
        }

        // A crash after exact account deletion is not mistaken for first run
        // while any recovery output exists. Explicit recovery can resume.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            _ = try fixture.privateDirectory(
                DeviceAttestationAuthority.recoveryGuardLeafName + "/operation-crashed"
            )
            try expectThrows(.bootstrapRecoveryRequired) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            try expect(keys.inserts.isEmpty, "guarded recovery was bootstrapped automatically")
            try expect(FileManager.default.fileExists(atPath: recovery.path), "recovery guard disappeared")
        }

        // A stale confirmation cannot move a substituted control namespace.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            _ = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let expected = try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                configuration: fixture.configuration
            )
            let old = fixture.root.appendingPathComponent("old-control", isDirectory: true)
            try FileManager.default.moveItem(at: fixture.control, to: old)
            try FileManager.default.createDirectory(at: fixture.control, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.control.path)
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-stale", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            try expectThrows(.recoveryAuthorizationInvalid) {
                _ = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                    configuration: fixture.configuration,
                    recoveryOperationRoot: operation,
                    expectedControlState: expected
                )
            }
            try expect(keys.deletes.isEmpty, "stale control confirmation reached Keychain deletion")
        }

        // If either exact delete fails, bootstrap is not attempted and the
        // remaining half-state stays blocked for another explicit retry.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-delete-failure", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            let authorization = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                configuration: fixture.configuration,
                recoveryOperationRoot: operation,
                expectedControlState: try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                    configuration: fixture.configuration
                )
            )
            keys.deleteFailureAccount = fixture.configuration.publicAnchorAccount
            try expectThrows(.keychainFailure(errSecIO)) {
                _ = try DeviceAttestationAuthority.recoverForeground(
                    configuration: fixture.configuration,
                    keyStore: keys,
                    authorization: authorization
                )
            }
            try expect(keys.inserts.count == 2, "delete failure unexpectedly bootstrapped another key")
            try expect(keys.values[fixture.configuration.publicAnchorAccount] != nil, "failed anchor delete changed anchor")
        }
    }

    static func pathSymlinkModeAndACL() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let add = Process(); add.executableURL = URL(fileURLWithPath: "/bin/chmod")
            add.arguments = ["+a", "group:everyone deny delete", fixture.root.path]
            try add.run(); try expect(waitBounded(add, seconds: 2) && add.terminationStatus == 0, "deny ACL setup")
            _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore())
            let clear = Process(); clear.executableURL = URL(fileURLWithPath: "/bin/chmod"); clear.arguments = ["-N", fixture.root.path]
            try clear.run(); try expect(waitBounded(clear, seconds: 2) && clear.terminationStatus == 0, "deny ACL cleanup")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let outside = try fixture.privateDirectory("outside")
            try FileManager.default.createSymbolicLink(at: fixture.root.appendingPathComponent(".FulmarControl"), withDestinationURL: outside)
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore()) }
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore(); _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.control.path)
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore(); _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read", fixture.control.path]; try process.run()
            try expect(waitBounded(process, seconds: 2) && process.terminationStatus == 0, "bounded chmod failed")
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        }
    }

    static func preparedRenameCurrentOpaqueRoot() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
        let historical = source.appendingPathComponent("Backups", isDirectory: true)
        try FileManager.default.createDirectory(at: historical, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expect(Darwin.mkfifo(historical.appendingPathComponent("must-not-open").path, 0o600) == 0, "fifo")
        let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        let store = authority.makeProviderHistoryNamespaceMarkerStore()
        let current = try store.publish(.init(
            sourceParent: source, sourceLeaf: "Backups", destinationParent: destination, destinationLeaf: "historical-backups",
            namespaceName: "provider-history-backups", privacyEpoch: 7, receipt: Data("exact receipt".utf8)))
        try expect(current.state == .current && current.privacyEpoch == 7, "current fields")
        var metadata = stat()
        try expect(Darwin.lstat(destination.appendingPathComponent("historical-backups/must-not-open").path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFIFO, "opaque child was not preserved")
        let expected = destination.appendingPathComponent("historical-backups")
        let migration = source.appendingPathComponent("Migration")
        try FileManager.default.createDirectory(at: migration, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let migrationCurrent = try store.publish(.init(
            sourceParent: source, sourceLeaf: "Migration", destinationParent: destination, destinationLeaf: "historical-migration",
            namespaceName: "provider-history-migration", privacyEpoch: 7, receipt: Data("migration receipt".utf8)))
        keys.resetObservations()
        let states = try ProviderHistoryNamespaceMarkerStore.backgroundStates([
            .init(namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                  expectedReceipt: Data("exact receipt".utf8)),
            .init(namespaceName: "provider-history-migration", expectedURL: destination.appendingPathComponent("historical-migration"), expectedPrivacyEpoch: 7,
                  expectedReceipt: Data("migration receipt".utf8))
        ], configuration: fixture.configuration, keyStore: keys)
        try expect(states["provider-history-backups"] == .current(current)
            && states["provider-history-migration"] == .current(migrationCurrent), "per-namespace batch")
        try expect(keys.reads == [fixture.configuration.publicAnchorAccount] && keys.inserts.isEmpty, "batch anchor count")
        try expectThrows(.namespaceChanged) {
            _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                expectedReceipt: Data("changed receipt".utf8), configuration: fixture.configuration, keyStore: keys)
        }
        try FileManager.default.createDirectory(at: source.appendingPathComponent("Backups2"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expectThrows(.foregroundRequired) {
            _ = try store.publish(.init(sourceParent: source, sourceLeaf: "Backups2", destinationParent: destination,
                destinationLeaf: "historical-backups-2", namespaceName: "provider-history-backups", privacyEpoch: 8,
                receipt: Data("new receipt".utf8)))
        }
        try expect(FileManager.default.fileExists(atPath: source.appendingPathComponent("Backups2").path), "current collision moved source")
        let displaced = destination.appendingPathComponent("displaced")
        try FileManager.default.moveItem(at: expected, to: displaced)
        try FileManager.default.createDirectory(at: expected, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expectThrows(.namespaceChanged) {
            _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                expectedReceipt: Data("exact receipt".utf8),
                configuration: fixture.configuration, keyStore: keys)
        }
    }

    static func everyCrashWindow() throws {
        for phase: ProviderHistoryNamespacePublicationPhase in [.preparedWritten, .rootRenamedAndSynced, .currentWritten] {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
            try FileManager.default.createDirectory(at: source.appendingPathComponent("History"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let store = ProviderHistoryNamespaceMarkerStore(authority: authority, interruption: { $0 == phase })
            try expectThrows(.injectedInterruption(phase)) {
                _ = try store.publish(.init(sourceParent: source, sourceLeaf: "History", destinationParent: destination,
                    destinationLeaf: "historical-history", namespaceName: "history", privacyEpoch: 9, receipt: Data("receipt".utf8)))
            }
            guard case .foregroundRequired = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "history", expectedURL: source.appendingPathComponent("History"), expectedPrivacyEpoch: 9,
                expectedReceipt: Data("receipt".utf8),
                configuration: fixture.configuration, keyStore: keys) else { throw TestFailure.failed("prepared did not force foreground") }
            let current = try store.reconcilePrepared(namespaceName: "history")
            try expect(try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "history", expectedURL: destination.appendingPathComponent("historical-history"), expectedPrivacyEpoch: 9,
                expectedReceipt: Data("receipt".utf8),
                configuration: fixture.configuration, keyStore: keys) == .current(current), "reconcile")
        }
    }

    static func markerTamperAndDeadline() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
        try FileManager.default.createDirectory(at: source.appendingPathComponent("History"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        _ = try authority.makeProviderHistoryNamespaceMarkerStore().publish(.init(sourceParent: source, sourceLeaf: "History",
            destinationParent: destination, destinationLeaf: "old-history", namespaceName: "history", privacyEpoch: 3, receipt: Data("receipt".utf8)))
        let slot = Data(SHA256.hash(data: Data("history".utf8))).map { String(format: "%02x", $0) }.joined()
        let currentURL = fixture.control.appendingPathComponent(".namespace-\(slot).current")
        guard var envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: currentURL)) as? [String: Any],
              let payloadString = envelope["payload"] as? String,
              let payload = Data(base64Encoded: payloadString),
              var marker = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else { throw TestFailure.failed("marker JSON") }
        marker["leafName"] = "other"
        envelope["payload"] = try JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]).base64EncodedString()
        try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]).write(to: currentURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: currentURL.path)
        try expectThrows(.invalidSignature) { _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
            namespaceName: "history", expectedURL: destination.appendingPathComponent("old-history"), expectedPrivacyEpoch: 3,
            expectedReceipt: Data("receipt".utf8),
            configuration: fixture.configuration, keyStore: keys) }
        let second = try Fixture(); defer { second.cleanup() }
        let invalid = DeviceAttestationAuthority.Configuration(controlParent: second.root, operationDuration: .infinity)
        try expectThrows(.invalidConfiguration) { _ = try DeviceAttestationAuthority.openForeground(configuration: invalid, keyStore: MemoryKeyStore()) }
        try expect(!FileManager.default.fileExists(atPath: second.root.appendingPathComponent(".FulmarControl").path), "invalid deadline mutated")
    }

    static func harnessHomeCapabilityTamperSwapAndCrash() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receipt = home.appendingPathComponent(".local-harness-home.json")
            try Data("exact-receipt".utf8).write(to: receipt)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
            let keys = MemoryKeyStore()
            guard case .absent = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                expectedPrivacyEpoch: 3,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("unpublished home was not absent") }
            try expect(keys.reads.isEmpty && keys.inserts.isEmpty, "absent home touched Keychain")

            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let capability = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                privacyEpoch: 3
            )
            try capability.withBorrowedDescriptor { descriptor in
                var metadata = stat()
                try expect(Darwin.fstat(descriptor, &metadata) == 0, "retained home descriptor")
                try expect(
                    capability.record.inode == UInt64(truncatingIfNeeded: metadata.st_ino),
                    "retained descriptor identity"
                )
            }
            keys.resetObservations()
            guard case .current(let backgroundCapability) = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                expectedPrivacyEpoch: 3,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("signed home not current") }
            try expect(
                backgroundCapability.record == capability.record,
                "background capability changed"
            )
            try expect(
                keys.reads == [fixture.configuration.publicAnchorAccount] && keys.inserts.isEmpty,
                "background home queried more than public anchor"
            )

            try Data("changed-receipt".utf8).write(to: receipt, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
            try expectThrows(.namespaceChanged) {
                _ = try HarnessHomeAttestationStore.backgroundState(
                    rootURL: home,
                    receiptLeafName: receipt.lastPathComponent,
                    expectedPrivacyEpoch: 3,
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
        }

        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receiptName = ".local-harness-home.json"
            try Data("receipt".utf8).write(to: home.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: home.appendingPathComponent(receiptName).path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 4
            )
            let displaced = fixture.root.appendingPathComponent("displaced")
            try FileManager.default.moveItem(at: home, to: displaced)
            let replacement = try fixture.privateDirectory("HarnessHome")
            try Data("receipt".utf8).write(to: replacement.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: replacement.appendingPathComponent(receiptName).path
            )
            try expectThrows(.namespaceChanged) {
                _ = try HarnessHomeAttestationStore.backgroundState(
                    rootURL: replacement,
                    receiptLeafName: receiptName,
                    expectedPrivacyEpoch: 4,
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
        }

        for phase: HarnessHomeAttestationPublicationPhase in [.preparedWritten, .currentWritten] {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receiptName = ".local-harness-home.json"
            try Data("receipt-\(phase.rawValue)".utf8)
                .write(to: home.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: home.appendingPathComponent(receiptName).path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let crashing = HarnessHomeAttestationStore(
                authority: authority,
                interruption: { $0 == phase }
            )
            do {
                _ = try crashing.establishCurrent(
                    rootURL: home,
                    receiptLeafName: receiptName,
                    privacyEpoch: 5
                )
                throw TestFailure.failed("expected home interruption \(phase)")
            } catch DeviceAttestationError.harnessHomeInjectedInterruption(let actual) {
                try expect(actual == phase, "wrong home interruption")
            }
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("home crash was not foreground-required") }
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 5
            )
            guard case .current = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("home crash did not reconcile") }
        }
    }

    static func harnessHomeRotationCrashRecovery() throws {
        let phases: [HarnessHomeAttestationRotationPhase] = [
            .preparedWritten,
            .previousCurrentPreserved,
            .previousCurrentRemoved,
            .replacementCurrentWritten,
            .completionWritten
        ]
        for phase in phases {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let receiptName = ".local-harness-home.json"
            let home = try fixture.privateDirectory("HarnessHome")
            let oldReceipt = home.appendingPathComponent(receiptName)
            try Data("old-receipt".utf8).write(to: oldReceipt)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: oldReceipt.path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 4
            )
            let operationID = UUID()
            let recovery = try fixture.privateDirectory("HarnessHomeRecovery")
            let staging = recovery.appendingPathComponent("repairing", isDirectory: true)
            try FileManager.default.createDirectory(
                at: staging,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let newReceipt = staging.appendingPathComponent(receiptName)
            try Data("new-receipt".utf8).write(to: newReceipt)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: newReceipt.path
            )
            let crashing = HarnessHomeAttestationStore(
                authority: authority,
                rotationInterruption: { $0 == phase }
            )
            let session = try crashing.makeRotationSession(
                rootURL: home,
                receiptLeafName: receiptName,
                targetPrivacyEpoch: 5
            )
            try session.begin(
                operationID: operationID,
                choice: .startClean,
                stagedRootURL: staging
            )
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("rotation intent admitted background work") }
            try expectThrows(.foregroundRequired) {
                _ = try crashing.establishCurrent(
                    rootURL: home,
                    receiptLeafName: receiptName,
                    privacyEpoch: 5
                )
            }

            var interrupted = false
            do {
                _ = try session.prepare(
                    operationID: operationID,
                    choice: .startClean,
                    stagedRootURL: staging
                )
            } catch DeviceAttestationError.harnessHomeRotationInjectedInterruption(let actual) {
                try expect(actual == phase, "wrong prepared rotation phase")
                interrupted = true
            }
            let historical = fixture.root.appendingPathComponent("historical-home", isDirectory: true)
            try FileManager.default.moveItem(at: home, to: historical)
            try FileManager.default.moveItem(at: staging, to: home)
            if !interrupted {
                do {
                    _ = try session.finalize(
                        operationID: operationID,
                        choice: .startClean
                    )
                } catch DeviceAttestationError.harnessHomeRotationInjectedInterruption(let actual) {
                    try expect(actual == phase, "wrong final rotation phase")
                    interrupted = true
                }
            }
            try expect(interrupted, "rotation phase did not interrupt: \(phase)")
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("interrupted rotation admitted background work") }

            let resumedStore = authority.makeHarnessHomeAttestationStore()
            let resumed = try resumedStore.makeRotationSession(
                rootURL: home,
                receiptLeafName: receiptName,
                targetPrivacyEpoch: 5
            )
            _ = try resumed.finalize(
                operationID: operationID,
                choice: .startClean
            )
            guard case .current(let capability) = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("rotation did not publish current") }
            try expect(capability.record.privacyEpoch == 5, "replacement epoch")
            let previous = fixture.control.appendingPathComponent(
                ".harness-home.previous-\(operationID.uuidString.lowercased())"
            )
            try expect(FileManager.default.fileExists(atPath: previous.path), "old current was not preserved")
        }
    }

    static func waitBounded(_ process: Process, seconds: TimeInterval) -> Bool {
        let duration = UInt64(seconds * 1_000_000_000)
        let start = DispatchTime.now().uptimeNanoseconds
        let (deadline, overflow) = start.addingReportingOverflow(duration)
        if overflow { process.terminate(); return false }
        while process.isRunning, DispatchTime.now().uptimeNanoseconds < deadline { usleep(10_000) }
        if process.isRunning { process.terminate(); return false }
        return true
    }
}
