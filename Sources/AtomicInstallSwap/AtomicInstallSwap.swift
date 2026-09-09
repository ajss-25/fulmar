import AppKit
import CryptoKit
import Darwin
import Foundation
import Security

public struct PrivateStableApplicationAttestation: Codable, Equatable, Sendable {
    public static let schemaVersion = 1
    public static let signingMode = "private-self-signed-v1"

    public let schemaVersion: Int
    public let signingMode: String
    public let identifier: String
    public let version: String
    public let build: Int
    public let cdHashHex: String
    public let leafCertificateSHA256Hex: String
    public let designatedRequirement: Data

    public init(
        identifier: String,
        version: String,
        build: Int,
        cdHashHex: String,
        leafCertificateSHA256Hex: String,
        designatedRequirement: Data
    ) {
        schemaVersion = Self.schemaVersion
        signingMode = Self.signingMode
        self.identifier = identifier
        self.version = version
        self.build = build
        self.cdHashHex = cdHashHex
        self.leafCertificateSHA256Hex = leafCertificateSHA256Hex
        self.designatedRequirement = designatedRequirement
    }

    public func validateShape() throws {
        guard schemaVersion == Self.schemaVersion,
              signingMode == Self.signingMode,
              identifier == "com.angadjairath.localharness",
              !version.isEmpty,
              version.utf8.count <= 128,
              build > 0,
              cdHashHex.count >= 40,
              cdHashHex.count <= 128,
              cdHashHex.count.isMultiple(of: 2),
              Self.lowerHex(cdHashHex),
              leafCertificateSHA256Hex.count == 64,
              Self.lowerHex(leafCertificateSHA256Hex),
              !designatedRequirement.isEmpty,
              designatedRequirement.count <= 4_096 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithData(
            designatedRequirement as CFData,
            [],
            &requirement
        ) == errSecSuccess,
              requirement != nil else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
    }

    public func encodedArgument() throws -> String {
        try validateShape()
        let encoded = try JSONEncoder().encode(self)
        guard encoded.count <= 6_144 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        return encoded.base64EncodedString()
    }

    public static func decodeArgument(_ value: String) throws -> Self {
        guard value.utf8.count <= 8_192,
              let bytes = Data(base64Encoded: value),
              bytes.count <= 6_144 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        do {
            let decoded = try JSONDecoder().decode(Self.self, from: bytes)
            try decoded.validateShape()
            return decoded
        } catch let error as AtomicInstallSwapError {
            throw error
        } catch {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
    }

    private static func lowerHex(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
        }
    }
}

public struct AtomicInstallIdentity: Codable, Equatable, Sendable {
    public let device: UInt64
    public let inode: UInt64
    public let owner: UInt32

    public init(device: UInt64, inode: UInt64, owner: UInt32) {
        self.device = device
        self.inode = inode
        self.owner = owner
    }
}

public struct AtomicInstallSwapReceipt: Equatable, Sendable {
    public let installed: AtomicInstallIdentity
    public let retainedRollback: AtomicInstallIdentity

    public init(installed: AtomicInstallIdentity, retainedRollback: AtomicInstallIdentity) {
        self.installed = installed
        self.retainedRollback = retainedRollback
    }
}

public enum AtomicInstallSwapError: Error, Equatable, LocalizedError {
    case invalidInvocation
    case invalidNonce
    case unsafeParent
    case unsafeLeaf
    case identityMismatch
    case crossDevice
    case applicationRunning
    case atomicSwapUnsupported
    case atomicSwapFailed
    case postSwapProofFailed
    case durabilityFailed
    case recoveryFailed
    case privateAttestationInvalid
    case injectedBeforeSwap
    case injectedAfterSwap

    public var errorDescription: String? {
        switch self {
        case .invalidInvocation:
            return "The atomic installer invocation is invalid."
        case .invalidNonce:
            return "The atomic installer stage identifier is invalid."
        case .unsafeParent:
            return "The installation directory failed its safety checks."
        case .unsafeLeaf:
            return "An application bundle failed its no-follow safety checks."
        case .identityMismatch:
            return "An application bundle changed before installation."
        case .crossDevice:
            return "The application bundles are not on the same filesystem."
        case .applicationRunning:
            return "Fulmar is still running, so no installation change was made."
        case .atomicSwapUnsupported:
            return "This filesystem does not support the required atomic installation operation."
        case .atomicSwapFailed:
            return "The atomic installation operation failed."
        case .postSwapProofFailed:
            return "The installed bundle identity could not be proven; the previous bundle was restored."
        case .durabilityFailed:
            return "The installation could not be durably committed; the previous bundle was restored."
        case .recoveryFailed:
            return "The previous bundle could not be proven restored. Manual recovery is required."
        case .privateAttestationInvalid:
            return "The private-stable application signature does not match the pinned signer."
        case .injectedBeforeSwap:
            return "The test fault occurred before the atomic installation operation."
        case .injectedAfterSwap:
            return "The test fault occurred after the atomic installation operation; the previous bundle was restored."
        }
    }
}

private struct OpenedInstallLeaf {
    let descriptor: Int32
    let identity: AtomicInstallIdentity
}

struct AtomicInstallParentMetadata {
    let owner: UInt32
    let group: UInt32
    let permissions: UInt16
    let isDirectory: Bool
    let hasExtendedACL: Bool
}

private enum AtomicInstallParentKind {
    case production
    case testing
}

struct AtomicInstallSwapTestHooks {
    var applicationIsRunning: () -> Bool = { false }
    var afterOpenBeforeFinalValidation: () throws -> Void = {}
    var afterExchangeBeforeProof: () throws -> Void = {}
    var validateStageContent: (Int32) throws -> Void = { _ in }
    var validateInstalledContent: (Int32) throws -> Void = { _ in }
    var exchange: (Int32, String, String) -> Int32 = AtomicInstallSwap.liveExchange
    var syncParent: (Int32) -> Int32 = AtomicInstallSwap.liveSync
}

public enum AtomicInstallSwap {
    public static let productionCurrentApplicationPath = "/Applications/Fulmar.app"
    public static let nonceByteCount = 64
    private static let productionParentPath = "/Applications"
    private static let currentLeaf = "Fulmar.app"
    private static let stagePrefix = ".Fulmar.install-stage."
    private static let stageSuffix = ".app"
    private static let expectedBundleIdentifier = "com.angadjairath.localharness"

    public static func stageLeaf(nonce: String) throws -> String {
        guard isValidNonce(nonce) else { throw AtomicInstallSwapError.invalidNonce }
        return "\(stagePrefix)\(nonce)\(stageSuffix)"
    }

    public static func performProduction(
        nonce: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity,
        expectedCandidate: PrivateStableApplicationAttestation
    ) throws -> AtomicInstallSwapReceipt {
        let stage = try stageLeaf(nonce: nonce)
        let expectedOwner = UInt32(geteuid())
        guard expectedCurrent.owner == expectedOwner,
              expectedStage.owner == expectedOwner else {
            throw AtomicInstallSwapError.identityMismatch
        }
        let hooks = AtomicInstallSwapTestHooks(
            applicationIsRunning: {
                productionApplicationIsRunning(stageLeaf: stage)
            },
            validateStageContent: { stageDescriptor in
                try validateProductionCandidate(
                    applicationDescriptor: stageDescriptor,
                    applicationURL: URL(
                        fileURLWithPath: productionParentPath,
                        isDirectory: true
                    ).appendingPathComponent(stage, isDirectory: true),
                    expectedStage: expectedStage,
                    expectedCandidate: expectedCandidate
                )
            },
            validateInstalledContent: { stageDescriptor in
                try validateProductionCandidate(
                    applicationDescriptor: stageDescriptor,
                    applicationURL: URL(
                        fileURLWithPath: productionCurrentApplicationPath,
                        isDirectory: true
                    ),
                    expectedStage: expectedStage,
                    expectedCandidate: expectedCandidate
                )
            }
        )
        return try perform(
            parentPath: productionParentPath,
            parentKind: .production,
            stageLeaf: stage,
            expectedCurrent: expectedCurrent,
            expectedStage: expectedStage,
            hooks: hooks
        )
    }

    static func performForTesting(
        parentDirectory: URL,
        nonce: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity,
        hooks: AtomicInstallSwapTestHooks = AtomicInstallSwapTestHooks()
    ) throws -> AtomicInstallSwapReceipt {
        let stage = try stageLeaf(nonce: nonce)
        return try perform(
            parentPath: parentDirectory.path,
            parentKind: .testing,
            stageLeaf: stage,
            expectedCurrent: expectedCurrent,
            expectedStage: expectedStage,
            hooks: hooks
        )
    }

    static func validateLeafForTesting(_ leaf: String) throws {
        guard validLeaf(leaf) else { throw AtomicInstallSwapError.unsafeLeaf }
    }

    static func identityForTesting(parentDirectory: URL, leaf: String) throws -> AtomicInstallIdentity {
        try validateLeafForTesting(leaf)
        let parent = try openParent(path: parentDirectory.path, kind: .testing)
        defer { _ = Darwin.close(parent) }
        return try namedIdentity(parentDescriptor: parent, leaf: leaf)
    }

    public static func privateStableAttestation(
        at application: URL
    ) throws -> PrivateStableApplicationAttestation {
        let descriptor = Darwin.open(
            application.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else { throw AtomicInstallSwapError.privateAttestationInvalid }
        defer { _ = Darwin.close(descriptor) }
        return try inspectPrivateStableApplication(
            applicationDescriptor: descriptor,
            applicationURL: application
        )
    }

    public static func validatePrivateStableApplication(
        at application: URL,
        expected: PrivateStableApplicationAttestation
    ) throws {
        let actual = try privateStableAttestation(at: application)
        guard actual == expected else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
    }

    static func privateStableAttestationForTesting(
        at application: URL
    ) throws -> PrivateStableApplicationAttestation {
        try privateStableAttestation(at: application)
    }

    static func validatePrivateStableApplicationForTesting(
        at application: URL,
        expected: PrivateStableApplicationAttestation
    ) throws {
        try validatePrivateStableApplication(at: application, expected: expected)
    }

    static func productionParentMetadataIsSafe(
        _ metadata: AtomicInstallParentMetadata,
        adminGroup: UInt32,
        wheelGroup: UInt32
    ) -> Bool {
        guard metadata.isDirectory,
              metadata.owner == 0,
              !metadata.hasExtendedACL else {
            return false
        }
        switch metadata.permissions {
        case 0o775:
            return metadata.group == adminGroup
        case 0o755:
            return metadata.group == adminGroup || metadata.group == wheelGroup
        default:
            return false
        }
    }

    static func liveExchange(parentDescriptor: Int32, first: String, second: String) -> Int32 {
        let result = first.withCString { firstPointer in
            second.withCString { secondPointer in
                renameatx_np(
                    parentDescriptor,
                    firstPointer,
                    parentDescriptor,
                    secondPointer,
                    UInt32(RENAME_SWAP)
                )
            }
        }
        return result == 0 ? 0 : errno
    }

    static func liveSync(parentDescriptor: Int32) -> Int32 {
        Darwin.fsync(parentDescriptor) == 0 ? 0 : errno
    }

    private static func perform(
        parentPath: String,
        parentKind: AtomicInstallParentKind,
        stageLeaf: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity,
        hooks: AtomicInstallSwapTestHooks
    ) throws -> AtomicInstallSwapReceipt {
        guard validLeaf(currentLeaf), validLeaf(stageLeaf),
              currentLeaf != stageLeaf,
              expectedCurrent.inode != 0,
              expectedStage.inode != 0,
              expectedCurrent != expectedStage,
              expectedCurrent.owner == UInt32(geteuid()),
              expectedStage.owner == UInt32(geteuid()) else {
            throw AtomicInstallSwapError.identityMismatch
        }
        guard !hooks.applicationIsRunning() else {
            throw AtomicInstallSwapError.applicationRunning
        }

        let parent = try openParent(path: parentPath, kind: parentKind)
        defer { _ = Darwin.close(parent) }
        let parentIdentity = identity(try descriptorMetadata(parent, parent: true))

        let current = try openLeaf(
            parentDescriptor: parent,
            leaf: currentLeaf,
            expected: expectedCurrent
        )
        defer { _ = Darwin.close(current.descriptor) }
        let stage = try openLeaf(
            parentDescriptor: parent,
            leaf: stageLeaf,
            expected: expectedStage
        )
        defer { _ = Darwin.close(stage.descriptor) }

        guard current.identity.device == parentIdentity.device,
              stage.identity.device == parentIdentity.device,
              current.identity.device == stage.identity.device else {
            throw AtomicInstallSwapError.crossDevice
        }

        try hooks.afterOpenBeforeFinalValidation()
        guard !hooks.applicationIsRunning() else {
            throw AtomicInstallSwapError.applicationRunning
        }
        try provePreSwapNames(
            parentDescriptor: parent,
            stageLeaf: stageLeaf,
            expectedCurrent: expectedCurrent,
            expectedStage: expectedStage
        )
        try hooks.validateStageContent(stage.descriptor)
        try provePreSwapNames(
            parentDescriptor: parent,
            stageLeaf: stageLeaf,
            expectedCurrent: expectedCurrent,
            expectedStage: expectedStage
        )

        let exchangeStatus = hooks.exchange(parent, currentLeaf, stageLeaf)
        guard exchangeStatus == 0 else {
            throw mappedExchangeError(exchangeStatus)
        }

        var postSwapError: AtomicInstallSwapError?
        do {
            try hooks.afterExchangeBeforeProof()
            guard !hooks.applicationIsRunning() else {
                throw AtomicInstallSwapError.applicationRunning
            }
            let installed = try namedIdentity(parentDescriptor: parent, leaf: currentLeaf)
            let retained = try namedIdentity(parentDescriptor: parent, leaf: stageLeaf)
            guard installed == expectedStage,
                  retained == expectedCurrent else {
                throw AtomicInstallSwapError.postSwapProofFailed
            }
            try hooks.validateInstalledContent(stage.descriptor)
            guard try namedIdentity(parentDescriptor: parent, leaf: currentLeaf) == expectedStage,
                  try namedIdentity(parentDescriptor: parent, leaf: stageLeaf) == expectedCurrent else {
                throw AtomicInstallSwapError.postSwapProofFailed
            }
            guard hooks.syncParent(parent) == 0 else {
                throw AtomicInstallSwapError.durabilityFailed
            }
            return AtomicInstallSwapReceipt(
                installed: installed,
                retainedRollback: retained
            )
        } catch let error as AtomicInstallSwapError {
            postSwapError = error
        } catch {
            postSwapError = .postSwapProofFailed
        }

        do {
            try recoverImmediateSwapBack(
                parentDescriptor: parent,
                stageLeaf: stageLeaf,
                expectedCurrent: expectedCurrent,
                expectedStage: expectedStage,
                hooks: hooks
            )
        } catch {
            throw AtomicInstallSwapError.recoveryFailed
        }
        throw postSwapError ?? AtomicInstallSwapError.postSwapProofFailed
    }

    private static func recoverImmediateSwapBack(
        parentDescriptor: Int32,
        stageLeaf: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity,
        hooks: AtomicInstallSwapTestHooks
    ) throws {
        var current = try namedIdentity(parentDescriptor: parentDescriptor, leaf: currentLeaf)
        var stage = try namedIdentity(parentDescriptor: parentDescriptor, leaf: stageLeaf)

        if current == expectedStage, stage == expectedCurrent {
            let recoveryStatus = hooks.exchange(parentDescriptor, currentLeaf, stageLeaf)
            guard recoveryStatus == 0 else { throw AtomicInstallSwapError.recoveryFailed }
            current = try namedIdentity(parentDescriptor: parentDescriptor, leaf: currentLeaf)
            stage = try namedIdentity(parentDescriptor: parentDescriptor, leaf: stageLeaf)
        }

        guard current == expectedCurrent,
              stage == expectedStage,
              hooks.syncParent(parentDescriptor) == 0 else {
            throw AtomicInstallSwapError.recoveryFailed
        }
    }

    private static func provePreSwapNames(
        parentDescriptor: Int32,
        stageLeaf: String,
        expectedCurrent: AtomicInstallIdentity,
        expectedStage: AtomicInstallIdentity
    ) throws {
        let current = try namedIdentity(parentDescriptor: parentDescriptor, leaf: currentLeaf)
        let stage = try namedIdentity(parentDescriptor: parentDescriptor, leaf: stageLeaf)
        guard current == expectedCurrent, stage == expectedStage else {
            throw AtomicInstallSwapError.identityMismatch
        }
    }

    private static func openParent(path: String, kind: AtomicInstallParentKind) throws -> Int32 {
        guard path.hasPrefix("/"), path.utf8.count <= 4_096,
              path == canonicalPath(path) else {
            throw AtomicInstallSwapError.unsafeParent
        }
        switch kind {
        case .production:
            guard path == productionParentPath else {
                throw AtomicInstallSwapError.unsafeParent
            }
        case .testing:
            let url = URL(fileURLWithPath: path, isDirectory: true)
            guard url.lastPathComponent.hasPrefix("FulmarAtomicInstallTests."),
                  url.deletingLastPathComponent().path == "/private/tmp" else {
                throw AtomicInstallSwapError.unsafeParent
            }
        }

        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw AtomicInstallSwapError.unsafeParent }
        do {
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0,
                  metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
                throw AtomicInstallSwapError.unsafeParent
            }
            let hasExtendedACL = try descriptorHasExtendedACL(
                descriptor,
                failure: .unsafeParent
            )
            switch kind {
            case .production:
                guard let admin = getgrnam("admin") else {
                    throw AtomicInstallSwapError.unsafeParent
                }
                let adminGroup = UInt32(admin.pointee.gr_gid)
                guard let wheel = getgrnam("wheel"),
                      productionParentMetadataIsSafe(
                        AtomicInstallParentMetadata(
                            owner: UInt32(metadata.st_uid),
                            group: UInt32(metadata.st_gid),
                            permissions: UInt16(metadata.st_mode & 0o7777),
                            isDirectory: true,
                            hasExtendedACL: hasExtendedACL
                        ),
                        adminGroup: adminGroup,
                        wheelGroup: UInt32(wheel.pointee.gr_gid)
                      ) else {
                    throw AtomicInstallSwapError.unsafeParent
                }
            case .testing:
                guard metadata.st_uid == geteuid(),
                      metadata.st_mode & 0o7777 == 0o700,
                      !hasExtendedACL else {
                    throw AtomicInstallSwapError.unsafeParent
                }
            }
            return descriptor
        } catch {
            _ = Darwin.close(descriptor)
            throw error
        }
    }

    private static func openLeaf(
        parentDescriptor: Int32,
        leaf: String,
        expected: AtomicInstallIdentity
    ) throws -> OpenedInstallLeaf {
        guard validLeaf(leaf) else { throw AtomicInstallSwapError.unsafeLeaf }
        let before = try namedIdentity(parentDescriptor: parentDescriptor, leaf: leaf)
        let descriptor = leaf.withCString {
            openat(parentDescriptor, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw AtomicInstallSwapError.unsafeLeaf }
        do {
            let opened = identity(try descriptorMetadata(descriptor, parent: false))
            let after = try namedIdentity(parentDescriptor: parentDescriptor, leaf: leaf)
            guard before == expected,
                  opened == expected,
                  after == expected else {
                throw AtomicInstallSwapError.identityMismatch
            }
            guard try descriptorHasExtendedACL(descriptor, failure: .unsafeLeaf) == false else {
                throw AtomicInstallSwapError.unsafeLeaf
            }
            return OpenedInstallLeaf(descriptor: descriptor, identity: opened)
        } catch {
            _ = Darwin.close(descriptor)
            throw error
        }
    }

    private static func namedIdentity(
        parentDescriptor: Int32,
        leaf: String
    ) throws -> AtomicInstallIdentity {
        guard validLeaf(leaf) else { throw AtomicInstallSwapError.unsafeLeaf }
        var metadata = stat()
        let status = leaf.withCString {
            fstatat(parentDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        guard status == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o022 == 0 else {
            throw AtomicInstallSwapError.unsafeLeaf
        }
        return identity(metadata)
    }

    private static func descriptorMetadata(
        _ descriptor: Int32,
        parent: Bool
    ) throws -> stat {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
            throw parent ? AtomicInstallSwapError.unsafeParent : AtomicInstallSwapError.unsafeLeaf
        }
        return metadata
    }

    private static func descriptorHasExtendedACL(
        _ descriptor: Int32,
        failure: AtomicInstallSwapError
    ) throws -> Bool {
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return false }
            throw failure
        }
        defer { _ = acl_free(UnsafeMutableRawPointer(accessControlList)) }
        return true
    }

    private static func identity(_ metadata: stat) -> AtomicInstallIdentity {
        AtomicInstallIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(metadata.st_ino),
            owner: UInt32(metadata.st_uid)
        )
    }

    private static func mappedExchangeError(_ status: Int32) -> AtomicInstallSwapError {
        if status == EXDEV { return .crossDevice }
        if status == ENOTSUP || status == EINVAL { return .atomicSwapUnsupported }
        return .atomicSwapFailed
    }

    private static func validateProductionCandidate(
        applicationDescriptor: Int32,
        applicationURL: URL,
        expectedStage: AtomicInstallIdentity,
        expectedCandidate: PrivateStableApplicationAttestation
    ) throws {
        do {
            try expectedCandidate.validateShape()
        } catch {
            throw AtomicInstallSwapError.identityMismatch
        }
        let descriptorIdentity = identity(
            try descriptorMetadata(applicationDescriptor, parent: false)
        )
        guard descriptorIdentity == expectedStage else {
            throw AtomicInstallSwapError.identityMismatch
        }
        let actual = try inspectPrivateStableApplication(
            applicationDescriptor: applicationDescriptor,
            applicationURL: applicationURL
        )
        guard actual == expectedCandidate,
              identity(try descriptorMetadata(applicationDescriptor, parent: false)) == expectedStage else {
            throw AtomicInstallSwapError.identityMismatch
        }
    }

    private static func inspectPrivateStableApplication(
        applicationDescriptor: Int32,
        applicationURL: URL
    ) throws -> PrivateStableApplicationAttestation {
        let pathComponents = applicationURL.path.split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard applicationURL.path.hasPrefix("/"),
              applicationURL.path.utf8.count <= 4_096,
              !applicationURL.path.contains("\0"),
              pathComponents.first?.isEmpty == true,
              pathComponents.dropFirst().allSatisfy({
                !$0.isEmpty && $0 != "." && $0 != ".."
              }) else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        let identityBefore = identity(
            try descriptorMetadata(applicationDescriptor, parent: false)
        )
        var initialNamedMetadata = stat()
        guard lstat(applicationURL.path, &initialNamedMetadata) == 0,
              initialNamedMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              identity(initialNamedMetadata) == identityBefore else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            applicationURL as CFURL,
            [],
            &staticCode
        ) == errSecSuccess,
              let staticCode else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        let strictFlags = SecCSFlags(
            rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode
        )
        guard SecStaticCodeCheckValidity(staticCode, strictFlags, nil) == errSecSuccess else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation),
            &signingInformation
        ) == errSecSuccess,
              let values = signingInformation as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              identifier == expectedBundleIdentifier,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64,
              let certificates = values[kSecCodeInfoCertificates as String] as? [SecCertificate],
              certificates.count == 1,
              let certificate = certificates.first else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        if let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
           !team.isEmpty {
            // This trust mode is deliberately unavailable to Developer-ID
            // signatures. Public releases continue through the separate
            // team-bound update attestation policy.
            throw AtomicInstallSwapError.privateAttestationInvalid
        }

        guard let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate),
              let subject = SecCertificateCopyNormalizedSubjectSequence(certificate),
              issuer as Data == subject as Data else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(
            certificate,
            SecPolicyCreateBasicX509(),
            &trust
        ) == errSecSuccess,
              let trust,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        var trustError: CFError?
        guard !SecTrustEvaluateWithError(trust, &trustError),
              let trustError,
              CFErrorGetDomain(trustError) == kCFErrorDomainOSStatus,
              CFErrorGetCode(trustError) == CFIndex(errSecNotTrusted) else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }

        guard let rawRequirement = values[kSecCodeInfoDesignatedRequirement as String],
              CFGetTypeID(rawRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        let requirement = unsafeBitCast(rawRequirement as AnyObject, to: SecRequirement.self)
        var requirementBytes: CFData?
        guard SecRequirementCopyData(requirement, [], &requirementBytes) == errSecSuccess,
              let requirementBytes,
              SecStaticCodeCheckValidity(staticCode, strictFlags, requirement) == errSecSuccess else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }

        let metadata = try privateBundleMetadata(applicationDescriptor: applicationDescriptor)
        var namedMetadata = stat()
        guard lstat(applicationURL.path, &namedMetadata) == 0,
              namedMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              identity(namedMetadata) == identityBefore,
              metadata.identifier == identifier,
              identity(try descriptorMetadata(applicationDescriptor, parent: false)) == identityBefore else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        let certificateData = SecCertificateCopyData(certificate) as Data
        let attestation = PrivateStableApplicationAttestation(
            identifier: identifier,
            version: metadata.version,
            build: metadata.build,
            cdHashHex: cdHash.map { String(format: "%02x", $0) }.joined(),
            leafCertificateSHA256Hex: SHA256.hash(data: certificateData)
                .map { String(format: "%02x", $0) }
                .joined(),
            designatedRequirement: requirementBytes as Data
        )
        try attestation.validateShape()
        return attestation
    }

    private static func privateBundleMetadata(
        applicationDescriptor: Int32
    ) throws -> (identifier: String, version: String, build: Int) {
        let contentsDescriptor = "Contents".withCString {
            openat(
                applicationDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard contentsDescriptor >= 0 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        defer { _ = Darwin.close(contentsDescriptor) }
        var contentsMetadata = stat()
        guard fstat(contentsDescriptor, &contentsMetadata) == 0,
              contentsMetadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              contentsMetadata.st_uid == geteuid() else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }

        let informationDescriptor = "Info.plist".withCString {
            openat(contentsDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard informationDescriptor >= 0 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        defer { _ = Darwin.close(informationDescriptor) }
        var before = stat()
        guard fstat(informationDescriptor, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_size > 0,
              before.st_size <= 1_048_576 else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    informationDescriptor,
                    buffer.baseAddress?.advanced(by: offset),
                    buffer.count - offset
                )
            }
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                throw AtomicInstallSwapError.privateAttestationInvalid
            }
        }
        var after = stat()
        guard fstat(informationDescriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              let values = try PropertyListSerialization.propertyList(
                from: Data(bytes),
                options: [],
                format: nil
              ) as? [String: Any],
              let identifier = values["CFBundleIdentifier"] as? String,
              identifier == expectedBundleIdentifier,
              let version = values["CFBundleShortVersionString"] as? String,
              !version.isEmpty,
              version.utf8.count <= 128,
              let buildString = values["CFBundleVersion"] as? String,
              let build = Int(buildString),
              build > 0,
              String(build) == buildString else {
            throw AtomicInstallSwapError.privateAttestationInvalid
        }
        return (identifier, version, build)
    }

    private static func validLeaf(_ leaf: String) -> Bool {
        let bytes = Array(leaf.utf8)
        return !bytes.isEmpty
            && bytes.count <= 255
            && leaf == leaf.precomposedStringWithCanonicalMapping
            && leaf != "."
            && leaf != ".."
            && !bytes.contains(UInt8(ascii: "/"))
            && !bytes.contains(0)
            && bytes.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }

    private static func isValidNonce(_ nonce: String) -> Bool {
        let bytes = Array(nonce.utf8)
        return bytes.count == nonceByteCount
            && bytes.allSatisfy { byte in
                (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                    || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
            }
    }

    private static func canonicalPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func productionApplicationIsRunning(stageLeaf: String) -> Bool {
        if NSRunningApplication.runningApplications(
            withBundleIdentifier: expectedBundleIdentifier
        ).contains(where: { !$0.isTerminated }) {
            return true
        }

        let protectedPrefixes = [
            "\(productionCurrentApplicationPath)/",
            "\(productionParentPath)/\(stageLeaf)/"
        ]
        var processIdentifiers = [pid_t](repeating: 0, count: 16_384)
        let count = proc_listallpids(
            &processIdentifiers,
            Int32(processIdentifiers.count * MemoryLayout<pid_t>.size)
        )
        guard count >= 0 else { return true }
        var pathBytes = [CChar](repeating: 0, count: 4_096)
        for processIdentifier in processIdentifiers.prefix(Int(count)) where processIdentifier > 1 {
            pathBytes.withUnsafeMutableBufferPointer { buffer in
                buffer.initialize(repeating: 0)
            }
            let length = proc_pidpath(
                processIdentifier,
                &pathBytes,
                UInt32(pathBytes.count)
            )
            guard length > 0 else { continue }
            let executable = String(cString: pathBytes)
            if protectedPrefixes.contains(where: { executable.hasPrefix($0) }) {
                return true
            }
        }
        return false
    }
}
