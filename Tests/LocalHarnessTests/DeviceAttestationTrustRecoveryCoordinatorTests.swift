import CryptoKit
import Darwin
import Foundation
import LocalHarnessDeviceAttestation
import Testing
@testable import LocalHarness

private struct DeviceTrustRecoveryFixture {
    static let leaves = [
        "HarnessHome", "HarnessHomeRecovery", "Backups",
        ".local-harness-state-recovery", "Migration",
        ".fulmar-migration-installing", "ProviderHistoryAuxiliaryRecovery",
        ".provider-history-auxiliary-transaction"
    ]

    let root: URL
    let support: URL
    let keys = LocalHarnessTestDeviceAttestationKeyStore()

    init() throws {
        guard let account = getpwuid(geteuid()),
              let home = account.pointee.pw_dir else {
            throw DeviceAttestationTrustRecoveryError.unsafeApplicationSupport
        }
        let candidateRoot = URL(fileURLWithPath: String(cString: home), isDirectory: true)
            .appendingPathComponent("Library/Caches/fulmar-trust-recovery-\(UUID().uuidString)", isDirectory: true)
        let candidateSupport = candidateRoot.appendingPathComponent("support", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: candidateSupport,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateRoot.path
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateSupport.path
            )
        } catch {
            try? FileManager.default.removeItem(at: candidateRoot)
            throw error
        }
        root = candidateRoot
        support = candidateSupport
    }

    func populateAllRoots() throws {
        for leaf in Self.leaves {
            let directory = support.appendingPathComponent(leaf, isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            try Data("opaque-\(leaf)".utf8).write(
                to: directory.appendingPathComponent("must-remain-unread.bin")
            )
        }
    }

    func createPartialTrust() throws {
        let configuration = ProviderHistoryDeviceAttestation.configuration(applicationSupport: support)
        _ = try DeviceAttestationAuthority.openForeground(configuration: configuration, keyStore: keys)
        keys.removeForTest(account: configuration.publicAnchorAccount)
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@Suite("Explicit device-attestation trust recovery")
struct DeviceAttestationTrustRecoveryCoordinatorTests {
    @Test("Detection and cancellation are mutation-free and Keychain-free")
    func detectionOnly() throws {
        let fixture = try DeviceTrustRecoveryFixture(); defer { fixture.cleanup() }
        try fixture.populateAllRoots()
        try fixture.createPartialTrust()
        fixture.keys.resetObservations()
        let coordinator = DeviceAttestationTrustRecoveryCoordinator(
            applicationSupport: fixture.support,
            keyStore: fixture.keys
        )
        _ = try coordinator.inspect()
        let observations = fixture.keys.observations()
        #expect(observations.reads.isEmpty)
        #expect(observations.inserts.isEmpty)
        #expect(observations.deletes.isEmpty)
        #expect(!FileManager.default.fileExists(
            atPath: fixture.support.appendingPathComponent("DeviceTrustRecovery").path
        ))
        for leaf in DeviceTrustRecoveryFixture.leaves {
            #expect(FileManager.default.fileExists(
                atPath: fixture.support.appendingPathComponent(leaf).path
            ))
        }
    }

    @Test("Every whole-root interruption remains recoverable without deletion")
    func everyRootCrashWindow() throws {
        for phase in DeviceTrustRecoveryFixture.leaves.indices {
            let fixture = try DeviceTrustRecoveryFixture(); defer { fixture.cleanup() }
            try fixture.populateAllRoots()
            try fixture.createPartialTrust()
            let firstID = UUID()
            let request = try DeviceAttestationTrustRecoveryCoordinator(
                applicationSupport: fixture.support,
                keyStore: fixture.keys,
                makeUUID: { firstID },
                interruption: { $0 == phase }
            ).inspect()
            #expect(throws: DeviceAttestationTrustRecoveryError.self) {
                _ = try DeviceAttestationTrustRecoveryCoordinator(
                    applicationSupport: fixture.support,
                    keyStore: fixture.keys,
                    makeUUID: { firstID },
                    interruption: { $0 == phase }
                ).recoverAfterExplicitConfirmation(request)
            }
            #expect(fixture.keys.observations().deletes.isEmpty)
            let firstOperation = fixture.support
                .appendingPathComponent("DeviceTrustRecovery", isDirectory: true)
                .appendingPathComponent("operation-\(firstID.uuidString.lowercased())", isDirectory: true)
            #expect(FileManager.default.fileExists(atPath: firstOperation.path))
            for leaf in DeviceTrustRecoveryFixture.leaves {
                let live = fixture.support.appendingPathComponent(leaf)
                let preserved = firstOperation.appendingPathComponent(leaf)
                #expect(FileManager.default.fileExists(atPath: live.path)
                    != FileManager.default.fileExists(atPath: preserved.path))
            }

            let resumed = DeviceAttestationTrustRecoveryCoordinator(
                applicationSupport: fixture.support,
                keyStore: fixture.keys,
                makeUUID: { UUID() }
            )
            let nextRequest = try resumed.inspect()
            let (receipt, authority) = try resumed.recoverAfterExplicitConfirmation(nextRequest)
            #expect(FileManager.default.fileExists(atPath: firstOperation.path))
            #expect(FileManager.default.fileExists(atPath: receipt.recoveryOperation.path))
            _ = try authority.sign(payload: Data("recovered".utf8), domain: "test.trust-recovery")
        }
    }

    @Test("A substituted root invalidates confirmation before mutation")
    func rootRaceFailsClosed() throws {
        let fixture = try DeviceTrustRecoveryFixture(); defer { fixture.cleanup() }
        try fixture.populateAllRoots()
        try fixture.createPartialTrust()
        let coordinator = DeviceAttestationTrustRecoveryCoordinator(
            applicationSupport: fixture.support,
            keyStore: fixture.keys
        )
        let request = try coordinator.inspect()
        let home = fixture.support.appendingPathComponent("HarnessHome", isDirectory: true)
        let displaced = fixture.support.appendingPathComponent("HarnessHome-old", isDirectory: true)
        try FileManager.default.moveItem(at: home, to: displaced)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
        #expect(throws: DeviceAttestationTrustRecoveryError.self) {
            _ = try coordinator.recoverAfterExplicitConfirmation(request)
        }
        #expect(fixture.keys.observations().deletes.isEmpty)
        #expect(!FileManager.default.fileExists(
            atPath: fixture.support.appendingPathComponent("DeviceTrustRecovery").path
        ))
    }

    @Test("A Keychain delete failure keeps new bootstrap blocked and retained")
    func deleteFailure() throws {
        let fixture = try DeviceTrustRecoveryFixture(); defer { fixture.cleanup() }
        try fixture.populateAllRoots()
        try fixture.createPartialTrust()
        let configuration = ProviderHistoryDeviceAttestation.configuration(applicationSupport: fixture.support)
        fixture.keys.deleteFailureAccount = configuration.publicAnchorAccount
        let coordinator = DeviceAttestationTrustRecoveryCoordinator(
            applicationSupport: fixture.support,
            keyStore: fixture.keys
        )
        let request = try coordinator.inspect()
        #expect(throws: DeviceAttestationError.self) {
            _ = try coordinator.recoverAfterExplicitConfirmation(request)
        }
        #expect(FileManager.default.fileExists(
            atPath: fixture.support.appendingPathComponent("DeviceTrustRecovery").path
        ))
        #expect(throws: DeviceAttestationError.self) {
            _ = try DeviceAttestationAuthority.openForeground(
                configuration: configuration,
                keyStore: fixture.keys
            )
        }
    }
}
