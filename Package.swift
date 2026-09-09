// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "LocalHarness",
    platforms: [
        .macOS(.v15)
    ],
    targets: [
        .target(
            name: "LocalHarnessSandboxPolicy",
            path: "Sources/SandboxPolicy"
        ),
        .target(
            name: "LocalHarnessApplicationSupportAdmission",
            path: "Sources/ApplicationSupportAdmission"
        ),
        .target(
            name: "LocalHarnessSchedulerWake",
            dependencies: ["LocalHarnessSandboxPolicy"],
            path: "Sources/SchedulerWake"
        ),
        .target(
            name: "LocalHarnessUpdateSecurity",
            path: "Sources/UpdateSecurity"
        ),
        .target(
            name: "LocalHarnessAtomicInstallSwap",
            path: "Sources/AtomicInstallSwap"
        ),
        .target(
            name: "LocalHarnessPrivateInstallCoordinator",
            dependencies: ["LocalHarnessAtomicInstallSwap"],
            path: "Sources/PrivateInstallCoordinator"
        ),
        .target(
            name: "LocalHarnessCredentialSecurity",
            path: "Sources/CredentialSecurity"
        ),
        .target(
            name: "LocalHarnessCredentialMigrationXPCProtocol",
            path: "Sources/CredentialMigrationXPCProtocol"
        ),
        .target(
            name: "LocalHarnessCredentialBrokerXPCProtocol",
            path: "Sources/CredentialBrokerXPCProtocol"
        ),
        .target(
            name: "LocalHarnessCredentialMigrationProcess",
            path: "Sources/CredentialMigrationProcess"
        ),
        .target(
            name: "LocalHarnessDeviceAttestation",
            path: "Sources/DeviceAttestationAuthority",
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "LocalHarness",
            dependencies: [
                "LocalHarnessUpdateSecurity",
                "LocalHarnessSandboxPolicy",
                "LocalHarnessApplicationSupportAdmission",
                "LocalHarnessCredentialMigrationXPCProtocol",
                "LocalHarnessCredentialMigrationProcess",
                "LocalHarnessDeviceAttestation"
            ],
            path: "Sources/LocalHarness"
        ),
        .executableTarget(
            name: "IconPacker",
            path: "Tools/IconPacker"
        ),
        .executableTarget(
            name: "LocalHarnessCredentialHelper",
            dependencies: [
                "LocalHarnessCredentialSecurity",
                "LocalHarnessCredentialBrokerXPCProtocol"
            ],
            path: "Tools/CredentialHelper"
        ),
        .executableTarget(
            name: "LocalHarnessCredentialBrokerService",
            dependencies: [
                "LocalHarnessCredentialBrokerXPCProtocol",
                "LocalHarnessCredentialSecurity"
            ],
            path: "Tools/CredentialBrokerService",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "LocalHarnessCredentialMigrationService",
            dependencies: [
                "LocalHarnessCredentialMigrationXPCProtocol",
                "LocalHarnessCredentialSecurity"
            ],
            path: "Tools/CredentialMigrationService",
            linkerSettings: [
                .linkedFramework("JavaScriptCore"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "LocalHarnessSchedulerHelper",
            dependencies: ["LocalHarnessSchedulerWake"],
            path: "Tools/SchedulerHelper"
        ),
        .executableTarget(
            name: "LocalHarnessUpdateHelper",
            dependencies: ["LocalHarnessUpdateSecurity"],
            path: "Tools/UpdateHelper"
        ),
        .executableTarget(
            name: "LocalHarnessAtomicInstallSwapHelper",
            dependencies: ["LocalHarnessAtomicInstallSwap"],
            path: "Tools/AtomicInstallSwapHelper"
        ),
        .executableTarget(
            name: "LocalHarnessPrivateInstallCoordinatorTool",
            dependencies: ["LocalHarnessPrivateInstallCoordinator"],
            path: "Tools/PrivateInstallCoordinator"
        ),
        .executableTarget(
            name: "LocalHarnessPrivateRollbackInspectorTool",
            dependencies: ["LocalHarnessPrivateInstallCoordinator"],
            path: "Tools/PrivateRollbackInspector"
        ),
        .executableTarget(
            name: "LocalHarnessSandboxRunner",
            dependencies: ["LocalHarnessSandboxPolicy"],
            path: "Tools/SandboxRunner"
        ),
        .executableTarget(
            name: "LocalHarnessRuntimeLease",
            path: "Tools/RuntimeLease"
        ),
        .executableTarget(
            name: "CredentialTransactionCrashProbe",
            dependencies: ["LocalHarnessCredentialSecurity"],
            path: "Tests/CredentialTransactionCrashProbe"
        ),
        .executableTarget(
            name: "PrivateInstallCrashProbe",
            dependencies: ["LocalHarnessPrivateInstallCoordinator"],
            path: "Tests/PrivateInstallCrashProbe"
        ),
        .executableTarget(
            name: "CredentialMigrationFDCollisionProbe",
            dependencies: ["LocalHarnessCredentialMigrationProcess"],
            path: "Tests/CredentialMigrationFDCollisionProbe"
        ),
        .executableTarget(
            name: "ApplicationSupportRootAdmissionProbe",
            dependencies: ["LocalHarnessApplicationSupportAdmission"],
            path: "Tests/ApplicationSupportRootAdmissionProbe"
        ),
        .testTarget(
            name: "LocalHarnessTests",
            dependencies: [
                "LocalHarness",
                "LocalHarnessApplicationSupportAdmission",
                "LocalHarnessAtomicInstallSwap",
                "LocalHarnessPrivateInstallCoordinator",
                "LocalHarnessCredentialSecurity",
                "LocalHarnessCredentialMigrationXPCProtocol",
                "LocalHarnessCredentialMigrationProcess",
                "LocalHarnessCredentialBrokerXPCProtocol",
                "LocalHarnessDeviceAttestation",
                "LocalHarnessSandboxPolicy",
                "LocalHarnessSchedulerWake",
                "LocalHarnessUpdateSecurity"
            ],
            path: "Tests/LocalHarnessTests"
        ),
        .executableTarget(
            name: "DeviceAttestationAuthorityTests",
            dependencies: ["LocalHarnessDeviceAttestation"],
            path: "Tests/DeviceAttestationAuthorityTests"
        )
    ],
    swiftLanguageModes: [.v5]
)
