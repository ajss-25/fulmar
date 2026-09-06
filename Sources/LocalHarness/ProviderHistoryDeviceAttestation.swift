import Foundation
import LocalHarnessDeviceAttestation

/// The single production trust configuration for every provider-history
/// namespace. Callers may keep an authority for one bounded foreground
/// operation, but must not retain it across an application lifecycle boundary.
/// Background callers use the same key store only through the authority's
/// noninteractive, read-only public-anchor verification path.
enum ProviderHistoryDeviceAttestation {
    struct Namespace: Equatable, Sendable {
        let name: String
        let leafName: String

        /// These bytes are deliberately content-independent. They attest that
        /// this exact whole-root namespace was created by the current Fulmar
        /// privacy epoch; no historical child is opened to compute them.
        var publicationReceipt: Data {
            Data(
                "fulmar-provider-history-namespace/v1\nnamespace=\(name)\nleaf=\(leafName)\nepoch=\(ProviderHistoryPrivacyEpoch.current)\n"
                    .utf8
            )
        }
    }

    static let keychainService = "com.angadjairath.localharness.device-attestation"
    static let backups = Namespace(name: "fulmar.backups.v1", leafName: "Backups")
    static let stateRecovery = Namespace(
        name: "fulmar.state-recovery.v1",
        leafName: ".local-harness-state-recovery"
    )
    static let migration = Namespace(
        name: "fulmar.runtime-migration.v1",
        leafName: "Migration"
    )
    /// Fixed so an interruption before the signed `.prepared` publication can
    /// be detected and preserved opaquely on the next startup. It is never
    /// silently adopted or deleted.
    static let migrationStagingLeafName = ".fulmar-migration-installing"

    static let auxiliaryNamespaces = [backups, stateRecovery, migration]

    static func configuration(
        applicationSupport: URL,
        operationDuration: TimeInterval = 5
    ) -> DeviceAttestationAuthority.Configuration {
        DeviceAttestationAuthority.Configuration(
            controlParent: applicationSupport.standardizedFileURL,
            operationDuration: operationDuration
        )
    }

    static func productionKeyStore() -> MacOSDeviceAttestationKeychain {
        MacOSDeviceAttestationKeychain(service: keychainService)
    }

    static func openForeground(
        applicationSupport: URL,
        operationDuration: TimeInterval = 5,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> DeviceAttestationAuthority {
        try DeviceAttestationAuthority.openForeground(
            configuration: configuration(
                applicationSupport: applicationSupport,
                operationDuration: operationDuration
            ),
            keyStore: keyStore
        )
    }
}
