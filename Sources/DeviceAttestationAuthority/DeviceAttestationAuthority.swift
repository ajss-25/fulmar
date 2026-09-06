import CryptoKit
import Darwin
import Foundation
import Security

public enum DeviceAttestationError: Error, Equatable, Sendable {
    case invalidConfiguration
    case deadlineExceeded
    case unsafeControlPath
    case unsafeControlFile
    case keychainFailure(OSStatus)
    case privateKeyMissing
    case publicAnchorMissing
    case keyMaterialMismatch
    case untrustedPreexistingPublicKey
    case malformedEnvelope
    case wrongDomain
    case invalidSignature
    case malformedMarker
    case namespaceChanged
    case destinationExists
    case renameFailed(Int32)
    case foregroundRequired
    case bootstrapRecoveryRequired
    case recoveryAuthorizationInvalid
    case injectedInterruption(ProviderHistoryNamespacePublicationPhase)
    case harnessHomeInjectedInterruption(HarnessHomeAttestationPublicationPhase)
    case harnessHomeRotationInjectedInterruption(HarnessHomeAttestationRotationPhase)
}

/// A deliberately tiny key store contract. Production uses the macOS Keychain;
/// tests can provide a process-local implementation without accessing live credentials.
public protocol DeviceAttestationKeyStore: Sendable {
    func read(account: String) throws -> Data?
    func insert(_ data: Data, account: String) throws
}

/// Narrow destructive surface used only after foreground recovery has already
/// preserved every provider/history root. Background verification never
/// receives this capability.
public protocol DeviceAttestationRecoverableKeyStore: DeviceAttestationKeyStore {
    func delete(account: String) throws
}

/// Noninteractive generic-password storage. Every query explicitly forbids authentication UI.
public struct MacOSDeviceAttestationKeychain: DeviceAttestationRecoverableKeyStore, Sendable {
    public let service: String
    public let accessGroup: String?

    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func read(account: String) throws -> Data? {
        var query = base(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // String values are the ABI values of kSecUseAuthenticationUI and
        // kSecUseAuthenticationUIFail. Spelling them avoids a deployment-target
        // deprecation warning while retaining the required fail-without-UI query.
        query["u_AuthUI"] = "u_AuthUIF"
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw DeviceAttestationError.keychainFailure(status)
        }
        return data
    }

    public func insert(_ data: Data, account: String) throws {
        var query = base(account: account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query["u_AuthUI"] = "u_AuthUIF"
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceAttestationError.keychainFailure(status)
        }
    }

    public func delete(account: String) throws {
        var query = base(account: account)
        query["u_AuthUI"] = "u_AuthUIF"
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DeviceAttestationError.keychainFailure(status)
        }
    }

    private func base(account: String) -> [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        if let accessGroup { value[kSecAttrAccessGroup as String] = accessGroup }
        return value
    }
}

public struct DeviceAttestationSignedEnvelope: Equatable, Sendable {
    public let encoded: Data
    public init(encoded: Data) { self.encoded = encoded }
}

public struct DeviceAttestationVerifier: Sendable {
    private let publicKey: Curve25519.Signing.PublicKey

    fileprivate init(publicKey: Curve25519.Signing.PublicKey) {
        self.publicKey = publicKey
    }

    public func verify(
        _ envelope: DeviceAttestationSignedEnvelope,
        expectedDomain: String
    ) throws -> Data {
        guard let object = try? JSONSerialization.jsonObject(with: envelope.encoded),
              let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Set(["version", "domain", "payload", "signature"]),
              exactInteger(dictionary["version"]) == 1,
              let domain = dictionary["domain"] as? String,
              let payloadString = dictionary["payload"] as? String,
              let signatureString = dictionary["signature"] as? String,
              let payload = Data(base64Encoded: payloadString),
              let signature = Data(base64Encoded: signatureString),
              signature.count == 64 else {
            throw DeviceAttestationError.malformedEnvelope
        }
        guard envelope.encoded == (try Self.encodeEnvelope(domain: domain, payload: payload, signature: signature)) else {
            throw DeviceAttestationError.malformedEnvelope
        }
        guard domain == expectedDomain else { throw DeviceAttestationError.wrongDomain }
        let message = try Self.signingMessage(domain: domain, payload: payload)
        guard publicKey.isValidSignature(signature, for: message) else {
            throw DeviceAttestationError.invalidSignature
        }
        return payload
    }

    fileprivate static func encodeEnvelope(domain: String, payload: Data, signature: Data) throws -> Data {
        let object: [String: Any] = [
            "domain": domain,
            "payload": payload.base64EncodedString(),
            "signature": signature.base64EncodedString(),
            "version": 1
        ]
        do { return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
        catch { throw DeviceAttestationError.malformedEnvelope }
    }

    fileprivate static func signingMessage(domain: String, payload: Data) throws -> Data {
        guard !domain.isEmpty,
              !domain.contains("\0"),
              domain.utf8.count <= 1_024,
              payload.count <= 1_048_576,
              let domainCount = UInt32(exactly: domain.utf8.count),
              let payloadCount = UInt64(exactly: payload.count) else {
            throw DeviceAttestationError.invalidConfiguration
        }
        var result = Data("Fulmar.DeviceAttestation.Envelope\0v1\0".utf8)
        appendBigEndian(domainCount, to: &result)
        result.append(contentsOf: domain.utf8)
        appendBigEndian(payloadCount, to: &result)
        result.append(payload)
        return result
    }
}

/// Foreground signing authority and background-verifier factory.
///
/// The external raw public key is useful to auxiliary agents, but it is never a trust root.
/// Trust is pinned by a separate SHA-256 digest stored in the Keychain.
public final class DeviceAttestationAuthority: @unchecked Sendable {
    public struct Configuration: Sendable {
        public let controlParent: URL
        public let privateKeyAccount: String
        public let publicAnchorAccount: String
        public let operationDuration: TimeInterval

        public init(
            controlParent: URL,
            privateKeyAccount: String = "device-attestation-signing-private-v1",
            publicAnchorAccount: String = "device-attestation-public-anchor-sha256-v1",
            operationDuration: TimeInterval = 5
        ) {
            self.controlParent = controlParent
            self.privateKeyAccount = privateKeyAccount
            self.publicAnchorAccount = publicAnchorAccount
            self.operationDuration = operationDuration
        }
    }

    public static let publicKeyFileName = "public-key.curve25519"
    public static let recoveryGuardLeafName = "DeviceTrustRecovery"

    public struct OpaqueControlIdentity: Equatable, Sendable {
        public let device: UInt64
        public let inode: UInt64
        public let kind: UInt16
        public let owner: UInt32
        public let permissions: UInt16
        public let linkCount: UInt64

        fileprivate init(_ metadata: stat) {
            device = UInt64(truncatingIfNeeded: metadata.st_dev)
            inode = UInt64(metadata.st_ino)
            kind = UInt16(metadata.st_mode & S_IFMT)
            owner = metadata.st_uid
            permissions = UInt16(metadata.st_mode & 0o7777)
            linkCount = UInt64(metadata.st_nlink)
        }

        fileprivate func matches(_ metadata: stat) -> Bool {
            self == OpaqueControlIdentity(metadata)
        }
    }

    public enum BootstrapRecoveryControlState: Equatable, Sendable {
        case absent
        case present(OpaqueControlIdentity)
    }

    /// Opaque proof that the exact device-attestation control namespace was
    /// either absent or moved whole into one user-approved recovery operation.
    /// Only `authorizeBootstrapRecovery` can create this value. It is consumed
    /// by the destructive foreground reset entrypoint; background code never
    /// receives either this proof or a destructive key-store capability.
    public struct BootstrapRecoveryAuthorization: Sendable {
        fileprivate let controlParentPath: String
        fileprivate let recoveryOperationPath: String
        fileprivate let privateKeyAccount: String
        fileprivate let publicAnchorAccount: String
    }

    private let keyStore: any DeviceAttestationKeyStore
    private let configuration: Configuration
    fileprivate let control: DeviceAttestationControlDirectory
    private let privateKey: Curve25519.Signing.PrivateKey

    /// Foreground-only bootstrap. Existing inconsistent halves are never replaced.
    public static func openForeground(
        configuration: Configuration,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> DeviceAttestationAuthority {
        try openForeground(
            configuration: configuration,
            keyStore: keyStore,
            permitsConfirmedRecoveryBootstrap: false
        )
    }

    private static func openForeground(
        configuration: Configuration,
        keyStore: any DeviceAttestationKeyStore,
        permitsConfirmedRecoveryBootstrap: Bool
    ) throws -> DeviceAttestationAuthority {
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        // Inspect both Keychain halves before creating any filesystem state.
        // A partial bootstrap or planted half must be detection-only until the
        // user explicitly preserves private state and authorizes recovery.
        let privateBytes = try keyStore.read(account: configuration.privateKeyAccount)
        try deadline.check()
        let anchor = try keyStore.read(account: configuration.publicAnchorAccount)
        try deadline.check()

        if privateBytes == nil, anchor != nil {
            throw DeviceAttestationError.privateKeyMissing
        }
        if privateBytes != nil, anchor == nil {
            throw DeviceAttestationError.publicAnchorMissing
        }

        let existingControl = try DeviceAttestationControlDirectory.openExistingIfPresent(
            beneath: configuration.controlParent,
            deadline: deadline
        )

        if privateBytes == nil, anchor == nil {
            if existingControl != nil {
                existingControl?.close()
                throw DeviceAttestationError.untrustedPreexistingPublicKey
            }
            if !permitsConfirmedRecoveryBootstrap,
               try opaqueNodeExists(
                    beneath: configuration.controlParent,
                    leaf: recoveryGuardLeafName,
                    deadline: deadline
               ) {
                throw DeviceAttestationError.bootstrapRecoveryRequired
            }
        } else if existingControl == nil {
            throw DeviceAttestationError.keyMaterialMismatch
        }

        let control = try existingControl ?? DeviceAttestationControlDirectory.openOrCreate(
            beneath: configuration.controlParent,
            deadline: deadline
        )
        do {
            let external = try control.readOptionalFile(
                named: publicKeyFileName,
                exactBytes: 32,
                deadline: deadline
            )
            let privateKey: Curve25519.Signing.PrivateKey
            if let privateBytes {
                guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateBytes) else {
                    throw DeviceAttestationError.keyMaterialMismatch
                }
                privateKey = key
            } else {
                guard external == nil else {
                    throw DeviceAttestationError.untrustedPreexistingPublicKey
                }
                privateKey = Curve25519.Signing.PrivateKey()
                try keyStore.insert(
                    privateKey.rawRepresentation,
                    account: configuration.privateKeyAccount
                )
            }

            let publicBytes = privateKey.publicKey.rawRepresentation
            let derivedAnchor = Data(SHA256.hash(data: publicBytes))
            if let anchor {
                guard constantTimeEqual(anchor, derivedAnchor) else {
                    throw DeviceAttestationError.keyMaterialMismatch
                }
            } else {
                try keyStore.insert(derivedAnchor, account: configuration.publicAnchorAccount)
            }

            if let external {
                guard constantTimeEqual(external, publicBytes) else {
                    throw DeviceAttestationError.keyMaterialMismatch
                }
            } else {
                try control.publishNewFile(
                    publicBytes,
                    named: publicKeyFileName,
                    deadline: deadline
                )
            }
            return DeviceAttestationAuthority(
                configuration: configuration,
                keyStore: keyStore,
                control: control,
                privateKey: privateKey
            )
        } catch {
            control.close()
            throw error
        }
    }

    /// Foreground-only, explicit recovery preparation. The exact control
    /// namespace is renamed whole into a private, same-volume recovery
    /// operation without inspecting any child. Existing recovery output is
    /// never overwritten. Callers must preserve provider/history roots first.
    public static func authorizeBootstrapRecovery(
        configuration: Configuration,
        recoveryOperationRoot: URL,
        expectedControlState: BootstrapRecoveryControlState
    ) throws -> BootstrapRecoveryAuthorization {
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        let support = try SecureDirectoryHandle.openExactPrivate(
            configuration.controlParent,
            deadline: deadline
        )
        defer { support.close() }
        let recovery = try SecureDirectoryHandle.openExactPrivate(
            recoveryOperationRoot,
            deadline: deadline
        )
        defer { recovery.close() }
        try requireStrictDescendant(
            recoveryOperationRoot,
            of: configuration.controlParent
                .appendingPathComponent(recoveryGuardLeafName, isDirectory: true)
        )
        var supportMetadata = stat()
        var recoveryMetadata = stat()
        guard Darwin.fstat(support.descriptor, &supportMetadata) == 0,
              Darwin.fstat(recovery.descriptor, &recoveryMetadata) == 0,
              supportMetadata.st_dev == recoveryMetadata.st_dev else {
            throw DeviceAttestationError.recoveryAuthorizationInvalid
        }

        if let controlParent = try openPrivateChildIfPresent(
            parent: support.descriptor,
            name: ".FulmarControl"
        ) {
            defer { Darwin.close(controlParent) }
            var before = stat()
            let sourceStatus = "DeviceAttestation".withCString {
                fstatat(controlParent, $0, &before, AT_SYMLINK_NOFOLLOW)
            }
            if sourceStatus == 0 {
                guard case .present(let expected) = expectedControlState,
                      expected.matches(before) else {
                    throw DeviceAttestationError.recoveryAuthorizationInvalid
                }
                var destination = stat()
                let destinationStatus = "DeviceAttestationControl".withCString {
                    fstatat(recovery.descriptor, $0, &destination, AT_SYMLINK_NOFOLLOW)
                }
                guard destinationStatus != 0, errno == ENOENT else {
                    throw DeviceAttestationError.destinationExists
                }
                let renameStatus = "DeviceAttestation".withCString { source in
                    "DeviceAttestationControl".withCString { target in
                        renameat(controlParent, source, recovery.descriptor, target)
                    }
                }
                guard renameStatus == 0,
                      fsync(controlParent) == 0,
                      fsync(recovery.descriptor) == 0 else {
                    throw DeviceAttestationError.renameFailed(errno)
                }
                var rebound = stat()
                guard "DeviceAttestationControl".withCString({
                    fstatat(recovery.descriptor, $0, &rebound, AT_SYMLINK_NOFOLLOW)
                }) == 0,
                      sameIdentity(before, rebound) else {
                    throw DeviceAttestationError.recoveryAuthorizationInvalid
                }
            } else if errno == ENOENT {
                guard expectedControlState == .absent else {
                    throw DeviceAttestationError.recoveryAuthorizationInvalid
                }
            } else {
                throw DeviceAttestationError.unsafeControlPath
            }
        } else {
            guard expectedControlState == .absent else {
                throw DeviceAttestationError.recoveryAuthorizationInvalid
            }
        }

        // Rebind absence after the rename. A peer-created replacement cannot
        // be silently authorized for deletion/reset.
        if let replacement = try DeviceAttestationControlDirectory.openExistingIfPresent(
            beneath: configuration.controlParent,
            deadline: deadline
        ) {
            replacement.close()
            throw DeviceAttestationError.recoveryAuthorizationInvalid
        }
        return BootstrapRecoveryAuthorization(
            controlParentPath: configuration.controlParent.standardizedFileURL.path,
            recoveryOperationPath: recoveryOperationRoot.standardizedFileURL.path,
            privateKeyAccount: configuration.privateKeyAccount,
            publicAnchorAccount: configuration.publicAnchorAccount
        )
    }

    /// Detection-only snapshot for binding one exact foreground recovery
    /// confirmation. It reads no Keychain item, creates no directory, and never
    /// enumerates a control child.
    public static func bootstrapRecoveryControlState(
        configuration: Configuration
    ) throws -> BootstrapRecoveryControlState {
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        let support = try SecureDirectoryHandle.openExactPrivate(
            configuration.controlParent,
            deadline: deadline
        )
        defer { support.close() }
        guard let controlParent = try openPrivateChildIfPresent(
            parent: support.descriptor,
            name: ".FulmarControl"
        ) else {
            return .absent
        }
        defer { Darwin.close(controlParent) }
        var metadata = stat()
        if "DeviceAttestation".withCString({
            fstatat(controlParent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            return .present(OpaqueControlIdentity(metadata))
        }
        if errno == ENOENT { return .absent }
        throw DeviceAttestationError.unsafeControlPath
    }

    /// Deletes only the two exact attestation Keychain accounts after the
    /// control namespace has been preserved and revalidated absent. Any
    /// deletion/read/bootstrap failure remains fail-closed and can be retried
    /// only through another explicit foreground recovery operation.
    public static func recoverForeground(
        configuration: Configuration,
        keyStore: any DeviceAttestationRecoverableKeyStore,
        authorization: BootstrapRecoveryAuthorization
    ) throws -> DeviceAttestationAuthority {
        guard authorization.controlParentPath == configuration.controlParent.standardizedFileURL.path,
              authorization.privateKeyAccount == configuration.privateKeyAccount,
              authorization.publicAnchorAccount == configuration.publicAnchorAccount,
              authorization.recoveryOperationPath.hasPrefix(
                configuration.controlParent
                    .appendingPathComponent(recoveryGuardLeafName, isDirectory: true)
                    .standardizedFileURL.path + "/"
              ) else {
            throw DeviceAttestationError.recoveryAuthorizationInvalid
        }
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        if let replacement = try DeviceAttestationControlDirectory.openExistingIfPresent(
            beneath: configuration.controlParent,
            deadline: deadline
        ) {
            replacement.close()
            throw DeviceAttestationError.recoveryAuthorizationInvalid
        }
        try keyStore.delete(account: configuration.privateKeyAccount)
        try keyStore.delete(account: configuration.publicAnchorAccount)
        guard try keyStore.read(account: configuration.privateKeyAccount) == nil,
              try keyStore.read(account: configuration.publicAnchorAccount) == nil else {
            throw DeviceAttestationError.recoveryAuthorizationInvalid
        }
        return try openForeground(
            configuration: configuration,
            keyStore: keyStore,
            permitsConfirmedRecoveryBootstrap: true
        )
    }

    /// Background-safe: reads the public anchor only. No private-key query is issued.
    public static func openBackgroundVerifier(
        configuration: Configuration,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> DeviceAttestationVerifier {
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        let control = try DeviceAttestationControlDirectory.openExisting(
            beneath: configuration.controlParent,
            deadline: deadline
        )
        defer { control.close() }
        guard let anchor = try keyStore.read(account: configuration.publicAnchorAccount) else {
            throw DeviceAttestationError.publicAnchorMissing
        }
        try deadline.check()
        guard anchor.count == SHA256.byteCount,
              let bytes = try control.readOptionalFile(
                named: publicKeyFileName,
                exactBytes: 32,
                deadline: deadline
              ),
              constantTimeEqual(Data(SHA256.hash(data: bytes)), anchor),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: bytes) else {
            throw DeviceAttestationError.keyMaterialMismatch
        }
        return DeviceAttestationVerifier(publicKey: publicKey)
    }

    public func sign(payload: Data, domain: String) throws -> DeviceAttestationSignedEnvelope {
        let message = try DeviceAttestationVerifier.signingMessage(domain: domain, payload: payload)
        let signature = try privateKey.signature(for: message)
        return DeviceAttestationSignedEnvelope(
            encoded: try DeviceAttestationVerifier.encodeEnvelope(
                domain: domain,
                payload: payload,
                signature: signature
            )
        )
    }

    public func verifier() -> DeviceAttestationVerifier {
        DeviceAttestationVerifier(publicKey: privateKey.publicKey)
    }

    public func makeProviderHistoryNamespaceMarkerStore() -> ProviderHistoryNamespaceMarkerStore {
        ProviderHistoryNamespaceMarkerStore(authority: self)
    }

    public func makeHarnessHomeAttestationStore() -> HarnessHomeAttestationStore {
        HarnessHomeAttestationStore(authority: self)
    }

    private init(
        configuration: Configuration,
        keyStore: any DeviceAttestationKeyStore,
        control: DeviceAttestationControlDirectory,
        privateKey: Curve25519.Signing.PrivateKey
    ) {
        self.configuration = configuration
        self.keyStore = keyStore
        self.control = control
        self.privateKey = privateKey
    }

    deinit { control.close() }
}

public enum ProviderHistoryNamespacePublicationPhase: String, Sendable {
    case preparedWritten
    case rootRenamedAndSynced
    case currentWritten
}

public enum HarnessHomeAttestationPublicationPhase: String, Sendable {
    case preparedWritten
    case currentWritten
}

public enum HarnessHomeAttestationRotationPhase: String, Sendable {
    case preparedWritten
    case previousCurrentPreserved
    case previousCurrentRemoved
    case replacementCurrentWritten
    case completionWritten
}

public enum HarnessHomeAttestationRecoveryChoice: String, Sendable {
    case settingsOnly
    case startClean
}

public struct HarnessHomeAttestationRecord: Equatable, Sendable {
    public let canonicalPath: String
    public let leafName: String
    public let device: UInt64
    public let inode: UInt64
    public let owner: UInt32
    public let mode: UInt16
    public let privacyEpoch: UInt64
    public let receiptSHA256: String

    fileprivate func encoded() throws -> Data {
        let object: [String: Any] = [
            "canonicalPath": canonicalPath,
            "device": String(device),
            "inode": String(inode),
            "leafName": leafName,
            "mode": String(mode),
            "owner": String(owner),
            "privacyEpoch": String(privacyEpoch),
            "receiptSHA256": receiptSHA256,
            "version": 1
        ]
        do { return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
        catch { throw DeviceAttestationError.malformedMarker }
    }

    fileprivate static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == [
                "canonicalPath", "device", "inode", "leafName", "mode", "owner",
                "privacyEpoch", "receiptSHA256", "version"
              ],
              exactInteger(object["version"]) == 1,
              let canonicalPath = object["canonicalPath"] as? String,
              let leafName = object["leafName"] as? String,
              validCanonicalPath(canonicalPath, leaf: leafName),
              let deviceText = object["device"] as? String,
              let device = parseCanonicalUInt64(deviceText),
              let inodeText = object["inode"] as? String,
              let inode = parseCanonicalUInt64(inodeText),
              let ownerText = object["owner"] as? String,
              let owner64 = parseCanonicalUInt64(ownerText),
              let owner = UInt32(exactly: owner64),
              let modeText = object["mode"] as? String,
              let mode64 = parseCanonicalUInt64(modeText),
              let mode = UInt16(exactly: mode64),
              mode & ~UInt16(0o7777) == 0,
              let epochText = object["privacyEpoch"] as? String,
              let epoch = parseCanonicalUInt64(epochText),
              let digest = object["receiptSHA256"] as? String,
              isLowerHexDigest(digest) else {
            throw DeviceAttestationError.malformedMarker
        }
        let record = Self(
            canonicalPath: canonicalPath,
            leafName: leafName,
            device: device,
            inode: inode,
            owner: owner,
            mode: mode,
            privacyEpoch: epoch,
            receiptSHA256: digest
        )
        guard try record.encoded() == data else { throw DeviceAttestationError.malformedMarker }
        return record
    }
}

/// Signed intent for one exact, user-approved historical-home replacement.
/// The old signed current envelope is either bound exactly or its absence is
/// bound explicitly; the replacement record is captured from the staged inode
/// but names the final canonical Harness-home path.
public struct HarnessHomeAttestationRotationRecord: Equatable, Sendable {
    public let operationID: UUID
    public let choice: HarnessHomeAttestationRecoveryChoice
    public let sourceCanonicalPath: String
    public let sourceLeafName: String
    public let destinationCanonicalPath: String
    public let destinationLeafName: String
    public let previousRecord: HarnessHomeAttestationRecord?
    public let previousEnvelopeSHA256: String?
    public let replacementRecord: HarnessHomeAttestationRecord

    fileprivate func encoded() throws -> Data {
        let previousRecordBytes = try previousRecord?.encoded()
        let object: [String: Any] = [
            "choice": choice.rawValue,
            "destinationCanonicalPath": destinationCanonicalPath,
            "destinationLeafName": destinationLeafName,
            "operationID": operationID.uuidString.lowercased(),
            "previousEnvelopeSHA256": previousEnvelopeSHA256 ?? "",
            "previousRecord": previousRecordBytes?.base64EncodedString() ?? "",
            "replacementRecord": try replacementRecord.encoded().base64EncodedString(),
            "sourceCanonicalPath": sourceCanonicalPath,
            "sourceLeafName": sourceLeafName,
            "version": 1
        ]
        do { return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
        catch { throw DeviceAttestationError.malformedMarker }
    }

    fileprivate static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 32_768,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == [
                "choice", "destinationCanonicalPath", "destinationLeafName",
                "operationID", "previousEnvelopeSHA256", "previousRecord",
                "replacementRecord", "sourceCanonicalPath", "sourceLeafName", "version"
              ],
              exactInteger(object["version"]) == 1,
              let operationText = object["operationID"] as? String,
              let operationID = UUID(uuidString: operationText),
              operationText == operationID.uuidString.lowercased(),
              let choiceText = object["choice"] as? String,
              let choice = HarnessHomeAttestationRecoveryChoice(rawValue: choiceText),
              let sourcePath = object["sourceCanonicalPath"] as? String,
              let sourceLeaf = object["sourceLeafName"] as? String,
              validCanonicalPath(sourcePath, leaf: sourceLeaf),
              let destinationPath = object["destinationCanonicalPath"] as? String,
              let destinationLeaf = object["destinationLeafName"] as? String,
              validCanonicalPath(destinationPath, leaf: destinationLeaf),
              sourcePath != destinationPath,
              let previousDigestText = object["previousEnvelopeSHA256"] as? String,
              let previousRecordText = object["previousRecord"] as? String,
              let replacementText = object["replacementRecord"] as? String,
              let replacementBytes = Data(base64Encoded: replacementText),
              let replacement = try? HarnessHomeAttestationRecord.decodeExact(replacementBytes),
              replacement.canonicalPath == destinationPath,
              replacement.leafName == destinationLeaf else {
            throw DeviceAttestationError.malformedMarker
        }
        let previousRecord: HarnessHomeAttestationRecord?
        let previousDigest: String?
        if previousRecordText.isEmpty, previousDigestText.isEmpty {
            previousRecord = nil
            previousDigest = nil
        } else {
            guard isLowerHexDigest(previousDigestText),
                  let previousBytes = Data(base64Encoded: previousRecordText) else {
                throw DeviceAttestationError.malformedMarker
            }
            previousRecord = try HarnessHomeAttestationRecord.decodeExact(previousBytes)
            previousDigest = previousDigestText
        }
        let value = Self(
            operationID: operationID,
            choice: choice,
            sourceCanonicalPath: sourcePath,
            sourceLeafName: sourceLeaf,
            destinationCanonicalPath: destinationPath,
            destinationLeafName: destinationLeaf,
            previousRecord: previousRecord,
            previousEnvelopeSHA256: previousDigest,
            replacementRecord: replacement
        )
        guard try value.encoded() == data else { throw DeviceAttestationError.malformedMarker }
        return value
    }
}

private struct HarnessHomeAttestationRotationIntent: Equatable, Sendable {
    let operationID: UUID
    let choice: HarnessHomeAttestationRecoveryChoice
    let sourceCanonicalPath: String
    let sourceLeafName: String
    let destinationCanonicalPath: String
    let destinationLeafName: String
    let sourceDevice: UInt64
    let sourceInode: UInt64
    let sourceOwner: UInt32
    let sourceMode: UInt16
    let targetPrivacyEpoch: UInt64
    let previousRecord: HarnessHomeAttestationRecord?
    let previousEnvelopeSHA256: String?

    func encoded() throws -> Data {
        let object: [String: Any] = [
            "choice": choice.rawValue,
            "destinationCanonicalPath": destinationCanonicalPath,
            "destinationLeafName": destinationLeafName,
            "operationID": operationID.uuidString.lowercased(),
            "previousEnvelopeSHA256": previousEnvelopeSHA256 ?? "",
            "previousRecord": try previousRecord?.encoded().base64EncodedString() ?? "",
            "sourceCanonicalPath": sourceCanonicalPath,
            "sourceDevice": String(sourceDevice),
            "sourceInode": String(sourceInode),
            "sourceLeafName": sourceLeafName,
            "sourceMode": String(sourceMode),
            "sourceOwner": String(sourceOwner),
            "targetPrivacyEpoch": String(targetPrivacyEpoch),
            "version": 1
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 32_768,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == [
                "choice", "destinationCanonicalPath", "destinationLeafName", "operationID",
                "previousEnvelopeSHA256", "previousRecord", "sourceCanonicalPath",
                "sourceDevice", "sourceInode", "sourceLeafName", "sourceMode", "sourceOwner",
                "targetPrivacyEpoch", "version"
              ],
              exactInteger(object["version"]) == 1,
              let operationText = object["operationID"] as? String,
              let operationID = UUID(uuidString: operationText),
              operationText == operationID.uuidString.lowercased(),
              let choiceText = object["choice"] as? String,
              let choice = HarnessHomeAttestationRecoveryChoice(rawValue: choiceText),
              let sourcePath = object["sourceCanonicalPath"] as? String,
              let sourceLeaf = object["sourceLeafName"] as? String,
              validCanonicalPath(sourcePath, leaf: sourceLeaf),
              let destinationPath = object["destinationCanonicalPath"] as? String,
              let destinationLeaf = object["destinationLeafName"] as? String,
              validCanonicalPath(destinationPath, leaf: destinationLeaf),
              sourcePath != destinationPath,
              let deviceText = object["sourceDevice"] as? String,
              let device = parseCanonicalUInt64(deviceText),
              let inodeText = object["sourceInode"] as? String,
              let inode = parseCanonicalUInt64(inodeText),
              let ownerText = object["sourceOwner"] as? String,
              let owner64 = parseCanonicalUInt64(ownerText),
              let owner = UInt32(exactly: owner64),
              let modeText = object["sourceMode"] as? String,
              let mode64 = parseCanonicalUInt64(modeText),
              let mode = UInt16(exactly: mode64),
              mode & ~UInt16(0o7777) == 0,
              let epochText = object["targetPrivacyEpoch"] as? String,
              let epoch = parseCanonicalUInt64(epochText),
              let previousDigestText = object["previousEnvelopeSHA256"] as? String,
              let previousRecordText = object["previousRecord"] as? String else {
            throw DeviceAttestationError.malformedMarker
        }
        let previousRecord: HarnessHomeAttestationRecord?
        let previousDigest: String?
        if previousRecordText.isEmpty, previousDigestText.isEmpty {
            previousRecord = nil
            previousDigest = nil
        } else {
            guard isLowerHexDigest(previousDigestText),
                  let previousBytes = Data(base64Encoded: previousRecordText) else {
                throw DeviceAttestationError.malformedMarker
            }
            previousRecord = try HarnessHomeAttestationRecord.decodeExact(previousBytes)
            previousDigest = previousDigestText
        }
        let value = Self(
            operationID: operationID,
            choice: choice,
            sourceCanonicalPath: sourcePath,
            sourceLeafName: sourceLeaf,
            destinationCanonicalPath: destinationPath,
            destinationLeafName: destinationLeaf,
            sourceDevice: device,
            sourceInode: inode,
            sourceOwner: owner,
            sourceMode: mode,
            targetPrivacyEpoch: epoch,
            previousRecord: previousRecord,
            previousEnvelopeSHA256: previousDigest
        )
        guard try value.encoded() == data else { throw DeviceAttestationError.malformedMarker }
        return value
    }
}

/// A verified live Harness-home descriptor. Consumers borrow this descriptor
/// synchronously; they never reopen the path after attestation.
public final class HarnessHomeAttestationCapability: @unchecked Sendable {
    public let record: HarnessHomeAttestationRecord
    private let lock = NSLock()
    private var descriptor: Int32

    fileprivate init(record: HarnessHomeAttestationRecord, descriptor: Int32) {
        self.record = record
        self.descriptor = descriptor
    }

    public func withBorrowedDescriptor<Value>(
        _ body: (Int32) throws -> Value
    ) throws -> Value {
        try lock.withLock {
            guard descriptor >= 0 else { throw DeviceAttestationError.namespaceChanged }
            return try body(descriptor)
        }
    }

    deinit {
        lock.withLock {
            if descriptor >= 0 {
                Darwin.close(descriptor)
                descriptor = -1
            }
        }
    }
}

public enum HarnessHomeAttestationBackgroundState: Sendable {
    case absent
    case foregroundRequired(HarnessHomeAttestationRecord)
    case current(HarnessHomeAttestationCapability)
}

/// Device-attested ownership of the exact current Harness home. The signed
/// record binds the canonical root path, live inode identity, privacy epoch,
/// and the digest of the raw descriptor-read ownership receipt.
public final class HarnessHomeAttestationStore: @unchecked Sendable {
    public static let preparedDomain =
        "com.fulmar.device-attestation/v1/harness-home/prepared"
    public static let currentDomain =
        "com.fulmar.device-attestation/v1/harness-home/current"
    public static let rotationPreparedDomain =
        "com.fulmar.device-attestation/v1/harness-home/rotation-prepared"
    public static let rotationIntentDomain =
        "com.fulmar.device-attestation/v1/harness-home/rotation-intent"
    public static let rotationCompletedDomain =
        "com.fulmar.device-attestation/v1/harness-home/rotation-completed"
    private static let preparedName = ".harness-home.prepared"
    private static let currentName = ".harness-home.current"
    private static let rotationPreparedName = ".harness-home.rotation.prepared"
    private static let rotationIntentName = ".harness-home.rotation.intent"
    private static let maximumReceiptBytes = 64 * 1_024

    private let authority: DeviceAttestationAuthority
    private let interruption: (@Sendable (HarnessHomeAttestationPublicationPhase) -> Bool)?
    private let rotationInterruption: (@Sendable (HarnessHomeAttestationRotationPhase) -> Bool)?

    public final class RotationSession: @unchecked Sendable {
        private let store: HarnessHomeAttestationStore
        fileprivate let rootURL: URL
        fileprivate let receiptLeafName: String
        fileprivate let targetPrivacyEpoch: UInt64
        fileprivate let previousEnvelope: Data?
        fileprivate let previousCapability: HarnessHomeAttestationCapability?
        fileprivate let isResumingSignedRotation: Bool

        fileprivate init(
            store: HarnessHomeAttestationStore,
            rootURL: URL,
            receiptLeafName: String,
            targetPrivacyEpoch: UInt64,
            previousEnvelope: Data?,
            previousCapability: HarnessHomeAttestationCapability?,
            isResumingSignedRotation: Bool
        ) {
            self.store = store
            self.rootURL = rootURL
            self.receiptLeafName = receiptLeafName
            self.targetPrivacyEpoch = targetPrivacyEpoch
            self.previousEnvelope = previousEnvelope
            self.previousCapability = previousCapability
            self.isResumingSignedRotation = isResumingSignedRotation
        }

        public func begin(
            operationID: UUID,
            choice: HarnessHomeAttestationRecoveryChoice,
            stagedRootURL: URL
        ) throws {
            try store.beginRotation(
                session: self,
                operationID: operationID,
                choice: choice,
                stagedRootURL: stagedRootURL
            )
        }

        @discardableResult
        public func prepare(
            operationID: UUID,
            choice: HarnessHomeAttestationRecoveryChoice,
            stagedRootURL: URL
        ) throws -> HarnessHomeAttestationRotationRecord {
            try store.prepareRotation(
                session: self,
                operationID: operationID,
                choice: choice,
                stagedRootURL: stagedRootURL
            )
        }

        public func finalize(
            operationID: UUID,
            choice: HarnessHomeAttestationRecoveryChoice
        ) throws -> HarnessHomeAttestationCapability {
            try store.finalizeRotation(
                session: self,
                operationID: operationID,
                choice: choice
            )
        }
    }

    @_spi(Testing) public init(
        authority: DeviceAttestationAuthority,
        interruption: (@Sendable (HarnessHomeAttestationPublicationPhase) -> Bool)? = nil,
        rotationInterruption: (@Sendable (HarnessHomeAttestationRotationPhase) -> Bool)? = nil
    ) {
        self.authority = authority
        self.interruption = interruption
        self.rotationInterruption = rotationInterruption
    }

    public static func backgroundState(
        rootURL: URL,
        receiptLeafName: String,
        expectedPrivacyEpoch: UInt64,
        configuration: DeviceAttestationAuthority.Configuration,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> HarnessHomeAttestationBackgroundState {
        try validateInput(rootURL: rootURL, receiptLeafName: receiptLeafName)
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        guard let control = try DeviceAttestationControlDirectory.openExistingIfPresent(
            beneath: configuration.controlParent,
            deadline: deadline
        ) else { return .absent }
        defer { control.close() }
        let prepared = try control.readOptionalFile(
            named: preparedName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        let current = try control.readOptionalFile(
            named: currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        let rotationPrepared = try control.readOptionalFile(
            named: rotationPreparedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        let rotationIntent = try control.readOptionalFile(
            named: rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        guard prepared != nil || current != nil || rotationPrepared != nil || rotationIntent != nil else {
            return .absent
        }
        let verifier = try DeviceAttestationAuthority.openBackgroundVerifier(
            configuration: configuration,
            keyStore: keyStore
        )
        if let rotationPrepared {
            let rotation = try decodeRotation(
                rotationPrepared,
                verifier: verifier,
                domain: rotationPreparedDomain
            )
            try validateExpected(
                rotation.replacementRecord,
                rootURL: rootURL,
                privacyEpoch: expectedPrivacyEpoch
            )
            return .foregroundRequired(rotation.replacementRecord)
        }
        if let rotationIntent {
            let intent = try decodeRotationIntent(
                rotationIntent,
                verifier: verifier
            )
            guard intent.destinationCanonicalPath == rootURL.standardizedFileURL.path,
                  intent.destinationLeafName == rootURL.lastPathComponent,
                  intent.targetPrivacyEpoch == expectedPrivacyEpoch else {
                throw DeviceAttestationError.namespaceChanged
            }
            let pendingRecord = intent.previousRecord ?? HarnessHomeAttestationRecord(
                canonicalPath: intent.destinationCanonicalPath,
                leafName: intent.destinationLeafName,
                device: intent.sourceDevice,
                inode: intent.sourceInode,
                owner: intent.sourceOwner,
                mode: intent.sourceMode,
                privacyEpoch: intent.targetPrivacyEpoch,
                receiptSHA256: String(repeating: "0", count: 64)
            )
            return .foregroundRequired(pendingRecord)
        }
        if let prepared {
            let record = try decode(
                prepared,
                verifier: verifier,
                domain: preparedDomain
            )
            try validateExpected(
                record,
                rootURL: rootURL,
                privacyEpoch: expectedPrivacyEpoch
            )
            return .foregroundRequired(record)
        }
        guard let current else { throw DeviceAttestationError.malformedMarker }
        let record = try decode(current, verifier: verifier, domain: currentDomain)
        return .current(try verifiedCapability(
            record,
            rootURL: rootURL,
            receiptLeafName: receiptLeafName,
            privacyEpoch: expectedPrivacyEpoch,
            deadline: deadline
        ))
    }

    /// Foreground-only idempotent publication/reconciliation. Missing state is
    /// published in two signed fsync-backed records; an interrupted prepared
    /// record is reconciled only when the exact root and receipt still match.
    public func establishCurrent(
        rootURL: URL,
        receiptLeafName: String,
        privacyEpoch: UInt64
    ) throws -> HarnessHomeAttestationCapability {
        try Self.validateInput(rootURL: rootURL, receiptLeafName: receiptLeafName)
        let deadline = try CheckedDeadline(duration: 5)
        let verifier = authority.verifier()
        let preparedBytes = try authority.control.readOptionalFile(
            named: Self.preparedName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        let currentBytes = try authority.control.readOptionalFile(
            named: Self.currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        let pendingRotationPrepared = try authority.control.readOptionalFile(
            named: Self.rotationPreparedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        let pendingRotationIntent = try authority.control.readOptionalFile(
            named: Self.rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        if pendingRotationPrepared != nil || pendingRotationIntent != nil {
            throw DeviceAttestationError.foregroundRequired
        }
        if let preparedBytes {
            let prepared = try Self.decode(
                preparedBytes,
                verifier: verifier,
                domain: Self.preparedDomain
            )
            let capability = try Self.verifiedCapability(
                prepared,
                rootURL: rootURL,
                receiptLeafName: receiptLeafName,
                privacyEpoch: privacyEpoch,
                deadline: deadline
            )
            if let currentBytes {
                let current = try Self.decode(
                    currentBytes,
                    verifier: verifier,
                    domain: Self.currentDomain
                )
                guard current == prepared else { throw DeviceAttestationError.namespaceChanged }
            } else {
                try write(
                    prepared,
                    named: Self.currentName,
                    domain: Self.currentDomain,
                    deadline: deadline
                )
            }
            try interrupt(.currentWritten)
            try authority.control.removeFileIfPresent(
                named: Self.preparedName,
                deadline: deadline
            )
            return capability
        }
        if let currentBytes {
            let current = try Self.decode(
                currentBytes,
                verifier: verifier,
                domain: Self.currentDomain
            )
            return try Self.verifiedCapability(
                current,
                rootURL: rootURL,
                receiptLeafName: receiptLeafName,
                privacyEpoch: privacyEpoch,
                deadline: deadline
            )
        }

        let capability = try Self.makeCapability(
            rootURL: rootURL,
            receiptLeafName: receiptLeafName,
            privacyEpoch: privacyEpoch,
            deadline: deadline
        )
        do {
            try write(
                capability.record,
                named: Self.preparedName,
                domain: Self.preparedDomain,
                deadline: deadline
            )
            try interrupt(.preparedWritten)
            try write(
                capability.record,
                named: Self.currentName,
                domain: Self.currentDomain,
                deadline: deadline
            )
            try interrupt(.currentWritten)
            try authority.control.removeFileIfPresent(
                named: Self.preparedName,
                deadline: deadline
            )
            return capability
        } catch {
            throw error
        }
    }

    /// Captures either the exact signed current-home capability or the exact
    /// absence of a current marker before a user-approved historical recovery
    /// begins. If a signed rotation is already durable, the session resumes
    /// only that record and does not infer intent from the live filesystem.
    public func makeRotationSession(
        rootURL: URL,
        receiptLeafName: String,
        targetPrivacyEpoch: UInt64
    ) throws -> RotationSession {
        try Self.validateInput(rootURL: rootURL, receiptLeafName: receiptLeafName)
        let deadline = try CheckedDeadline(duration: 5)
        let rotation = try authority.control.readOptionalFile(
            named: Self.rotationPreparedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        let rotationIntent = try authority.control.readOptionalFile(
            named: Self.rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        if rotation != nil || rotationIntent != nil {
            return RotationSession(
                store: self,
                rootURL: rootURL,
                receiptLeafName: receiptLeafName,
                targetPrivacyEpoch: targetPrivacyEpoch,
                previousEnvelope: nil,
                previousCapability: nil,
                isResumingSignedRotation: true
            )
        }
        if try authority.control.readOptionalFile(
            named: Self.preparedName,
            maximumBytes: 32_768,
            deadline: deadline
        ) != nil {
            throw DeviceAttestationError.foregroundRequired
        }
        let current = try authority.control.readOptionalFile(
            named: Self.currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        let capability: HarnessHomeAttestationCapability?
        if let current {
            let record = try Self.decode(
                current,
                verifier: authority.verifier(),
                domain: Self.currentDomain
            )
            guard record.privacyEpoch <= targetPrivacyEpoch else {
                throw DeviceAttestationError.namespaceChanged
            }
            capability = try Self.verifiedCapability(
                record,
                rootURL: rootURL,
                receiptLeafName: receiptLeafName,
                privacyEpoch: record.privacyEpoch,
                deadline: deadline
            )
        } else {
            capability = nil
        }
        return RotationSession(
            store: self,
            rootURL: rootURL,
            receiptLeafName: receiptLeafName,
            targetPrivacyEpoch: targetPrivacyEpoch,
            previousEnvelope: current,
            previousCapability: capability,
            isResumingSignedRotation: false
        )
    }

    private func beginRotation(
        session: RotationSession,
        operationID: UUID,
        choice: HarnessHomeAttestationRecoveryChoice,
        stagedRootURL: URL
    ) throws {
        let deadline = try CheckedDeadline(duration: 5)
        let existing = try authority.control.readOptionalFile(
            named: Self.rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        if let existing {
            let intent = try Self.decodeRotationIntent(existing, verifier: authority.verifier())
            try Self.validateRotationIntent(
                intent,
                operationID: operationID,
                choice: choice,
                sourceURL: stagedRootURL,
                destinationURL: session.rootURL,
                targetPrivacyEpoch: session.targetPrivacyEpoch
            )
            try Self.validateStagedIdentity(intent, stagedRootURL: stagedRootURL, deadline: deadline)
            return
        }
        guard !session.isResumingSignedRotation else {
            // A full prepared record may legitimately outlive its intent only
            // after completion finalization; otherwise absence is ambiguous.
            guard try authority.control.readOptionalFile(
                named: Self.rotationPreparedName,
                maximumBytes: 65_536,
                deadline: deadline
            ) != nil else {
                throw DeviceAttestationError.namespaceChanged
            }
            return
        }
        let current = try authority.control.readOptionalFile(
            named: Self.currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        guard Self.optionalDataEqual(current, session.previousEnvelope) else {
            throw DeviceAttestationError.namespaceChanged
        }
        if let previous = session.previousCapability {
            try Self.revalidateCapability(
                previous,
                rootURL: session.rootURL,
                receiptLeafName: session.receiptLeafName,
                expectedPrivacyEpoch: previous.record.privacyEpoch
            )
        } else if current != nil {
            throw DeviceAttestationError.namespaceChanged
        }
        let staged = try SecureDirectoryHandle.openExactPrivate(stagedRootURL, deadline: deadline)
        defer { staged.close() }
        var metadata = stat()
        guard Darwin.fstat(staged.descriptor, &metadata) == 0 else {
            throw DeviceAttestationError.namespaceChanged
        }
        let intent = HarnessHomeAttestationRotationIntent(
            operationID: operationID,
            choice: choice,
            sourceCanonicalPath: stagedRootURL.standardizedFileURL.path,
            sourceLeafName: stagedRootURL.lastPathComponent,
            destinationCanonicalPath: session.rootURL.standardizedFileURL.path,
            destinationLeafName: session.rootURL.lastPathComponent,
            sourceDevice: UInt64(truncatingIfNeeded: metadata.st_dev),
            sourceInode: UInt64(truncatingIfNeeded: metadata.st_ino),
            sourceOwner: metadata.st_uid,
            sourceMode: UInt16(metadata.st_mode & 0o7777),
            targetPrivacyEpoch: session.targetPrivacyEpoch,
            previousRecord: session.previousCapability?.record,
            previousEnvelopeSHA256: session.previousEnvelope.map(Self.digest)
        )
        let envelope = try authority.sign(
            payload: intent.encoded(),
            domain: Self.rotationIntentDomain
        )
        try authority.control.publishNewFile(
            envelope.encoded,
            named: Self.rotationIntentName,
            deadline: deadline
        )
    }

    private func prepareRotation(
        session: RotationSession,
        operationID: UUID,
        choice: HarnessHomeAttestationRecoveryChoice,
        stagedRootURL: URL
    ) throws -> HarnessHomeAttestationRotationRecord {
        let deadline = try CheckedDeadline(duration: 5)
        let existing = try authority.control.readOptionalFile(
            named: Self.rotationPreparedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        if let existing {
            let record = try Self.decodeRotation(
                existing,
                verifier: authority.verifier(),
                domain: Self.rotationPreparedDomain
            )
            try Self.validateRotationIntent(
                record,
                operationID: operationID,
                choice: choice,
                sourceURL: stagedRootURL,
                destinationURL: session.rootURL,
                targetPrivacyEpoch: session.targetPrivacyEpoch
            )
            _ = try Self.verifiedCapability(
                record.replacementRecord,
                rootURL: stagedRootURL,
                recordURL: session.rootURL,
                receiptLeafName: session.receiptLeafName,
                privacyEpoch: session.targetPrivacyEpoch,
                deadline: deadline
            )
            return record
        }
        guard let intentBytes = try authority.control.readOptionalFile(
            named: Self.rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        ) else { throw DeviceAttestationError.namespaceChanged }
        let intent = try Self.decodeRotationIntent(
            intentBytes,
            verifier: authority.verifier()
        )
        try Self.validateRotationIntent(
            intent,
            operationID: operationID,
            choice: choice,
            sourceURL: stagedRootURL,
            destinationURL: session.rootURL,
            targetPrivacyEpoch: session.targetPrivacyEpoch
        )
        try Self.validateStagedIdentity(intent, stagedRootURL: stagedRootURL, deadline: deadline)
        let current = try authority.control.readOptionalFile(
            named: Self.currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        if let previousDigest = intent.previousEnvelopeSHA256 {
            guard let current, Self.digest(current) == previousDigest else {
                throw DeviceAttestationError.namespaceChanged
            }
        } else if current != nil {
            throw DeviceAttestationError.namespaceChanged
        }
        let replacement = try Self.makeCapability(
            rootURL: stagedRootURL,
            recordURL: session.rootURL,
            receiptLeafName: session.receiptLeafName,
            privacyEpoch: session.targetPrivacyEpoch,
            deadline: deadline
        )
        let record = HarnessHomeAttestationRotationRecord(
            operationID: operationID,
            choice: choice,
            sourceCanonicalPath: stagedRootURL.standardizedFileURL.path,
            sourceLeafName: stagedRootURL.lastPathComponent,
            destinationCanonicalPath: session.rootURL.standardizedFileURL.path,
            destinationLeafName: session.rootURL.lastPathComponent,
            previousRecord: intent.previousRecord,
            previousEnvelopeSHA256: intent.previousEnvelopeSHA256,
            replacementRecord: replacement.record
        )
        try writeRotation(
            record,
            named: Self.rotationPreparedName,
            domain: Self.rotationPreparedDomain,
            deadline: deadline
        )
        try interruptRotation(.preparedWritten)
        return record
    }

    private func finalizeRotation(
        session: RotationSession,
        operationID: UUID,
        choice: HarnessHomeAttestationRecoveryChoice
    ) throws -> HarnessHomeAttestationCapability {
        let deadline = try CheckedDeadline(duration: 5)
        let completedName = Self.rotationCompletedName(operationID)
        let previousName = Self.previousCurrentName(operationID)
        let preparedBytes = try authority.control.readOptionalFile(
            named: Self.rotationPreparedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        let completedBytes = try authority.control.readOptionalFile(
            named: completedName,
            maximumBytes: 65_536,
            deadline: deadline
        )
        let record: HarnessHomeAttestationRotationRecord
        if let preparedBytes {
            record = try Self.decodeRotation(
                preparedBytes,
                verifier: authority.verifier(),
                domain: Self.rotationPreparedDomain
            )
        } else if let completedBytes {
            record = try Self.decodeRotation(
                completedBytes,
                verifier: authority.verifier(),
                domain: Self.rotationCompletedDomain
            )
        } else {
            throw DeviceAttestationError.foregroundRequired
        }
        try Self.validateRotationIntent(
            record,
            operationID: operationID,
            choice: choice,
            sourceURL: URL(fileURLWithPath: record.sourceCanonicalPath),
            destinationURL: session.rootURL,
            targetPrivacyEpoch: session.targetPrivacyEpoch
        )
        let capability = try Self.verifiedCapability(
            record.replacementRecord,
            rootURL: session.rootURL,
            receiptLeafName: session.receiptLeafName,
            privacyEpoch: session.targetPrivacyEpoch,
            deadline: deadline
        )

        let archived = try authority.control.readOptionalFile(
            named: previousName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        var current = try authority.control.readOptionalFile(
            named: Self.currentName,
            maximumBytes: 32_768,
            deadline: deadline
        )
        if let previousDigest = record.previousEnvelopeSHA256 {
            if let archived {
                guard Self.digest(archived) == previousDigest else {
                    throw DeviceAttestationError.namespaceChanged
                }
            } else {
                guard let current, Self.digest(current) == previousDigest else {
                    throw DeviceAttestationError.namespaceChanged
                }
                try authority.control.publishNewFile(
                    current,
                    named: previousName,
                    deadline: deadline
                )
                try interruptRotation(.previousCurrentPreserved)
            }
            if let oldCurrent = current, Self.digest(oldCurrent) == previousDigest {
                try authority.control.removeFileIfPresent(
                    named: Self.currentName,
                    deadline: deadline
                )
                try interruptRotation(.previousCurrentRemoved)
                current = nil
            }
        } else {
            guard archived == nil else { throw DeviceAttestationError.namespaceChanged }
        }

        let expectedCurrent = try authority.sign(
            payload: record.replacementRecord.encoded(),
            domain: Self.currentDomain
        ).encoded
        if let current {
            let decoded = try Self.decode(
                current,
                verifier: authority.verifier(),
                domain: Self.currentDomain
            )
            guard decoded == record.replacementRecord else {
                throw DeviceAttestationError.namespaceChanged
            }
        } else {
            try authority.control.publishNewFile(
                expectedCurrent,
                named: Self.currentName,
                deadline: deadline
            )
            try interruptRotation(.replacementCurrentWritten)
        }

        if let completedBytes {
            let completed = try Self.decodeRotation(
                completedBytes,
                verifier: authority.verifier(),
                domain: Self.rotationCompletedDomain
            )
            guard completed == record else { throw DeviceAttestationError.namespaceChanged }
        } else {
            try writeRotation(
                record,
                named: completedName,
                domain: Self.rotationCompletedDomain,
                deadline: deadline
            )
            try interruptRotation(.completionWritten)
        }
        if preparedBytes != nil {
            try authority.control.removeFileIfPresent(
                named: Self.rotationPreparedName,
                deadline: deadline
            )
        }
        if let intentBytes = try authority.control.readOptionalFile(
            named: Self.rotationIntentName,
            maximumBytes: 65_536,
            deadline: deadline
        ) {
            let intent = try Self.decodeRotationIntent(
                intentBytes,
                verifier: authority.verifier()
            )
            guard intent.operationID == record.operationID,
                  intent.choice == record.choice,
                  intent.sourceCanonicalPath == record.sourceCanonicalPath,
                  intent.destinationCanonicalPath == record.destinationCanonicalPath,
                  intent.previousRecord == record.previousRecord,
                  intent.previousEnvelopeSHA256 == record.previousEnvelopeSHA256 else {
                throw DeviceAttestationError.namespaceChanged
            }
            try authority.control.removeFileIfPresent(
                named: Self.rotationIntentName,
                deadline: deadline
            )
        }
        return capability
    }

    /// Rebinds a previously verified retained descriptor to the exact live
    /// pathname and raw ownership receipt immediately before a child launch.
    /// No Keychain access or filesystem mutation occurs.
    public static func revalidateCapability(
        _ capability: HarnessHomeAttestationCapability,
        rootURL: URL,
        receiptLeafName: String,
        expectedPrivacyEpoch: UInt64,
        operationDuration: TimeInterval = 5
    ) throws {
        try validateInput(rootURL: rootURL, receiptLeafName: receiptLeafName)
        let deadline = try CheckedDeadline(duration: operationDuration)
        let rebound = try verifiedCapability(
            capability.record,
            rootURL: rootURL,
            receiptLeafName: receiptLeafName,
            privacyEpoch: expectedPrivacyEpoch,
            deadline: deadline
        )
        try capability.withBorrowedDescriptor { retained in
            try rebound.withBorrowedDescriptor { live in
                var retainedMetadata = stat()
                var liveMetadata = stat()
                guard Darwin.fstat(retained, &retainedMetadata) == 0,
                      Darwin.fstat(live, &liveMetadata) == 0,
                      sameIdentity(retainedMetadata, liveMetadata) else {
                    throw DeviceAttestationError.namespaceChanged
                }
            }
        }
    }

    private static func makeCapability(
        rootURL: URL,
        receiptLeafName: String,
        privacyEpoch: UInt64,
        deadline: CheckedDeadline
    ) throws -> HarnessHomeAttestationCapability {
        try makeCapability(
            rootURL: rootURL,
            recordURL: rootURL,
            receiptLeafName: receiptLeafName,
            privacyEpoch: privacyEpoch,
            deadline: deadline
        )
    }

    private static func makeCapability(
        rootURL: URL,
        recordURL: URL,
        receiptLeafName: String,
        privacyEpoch: UInt64,
        deadline: CheckedDeadline
    ) throws -> HarnessHomeAttestationCapability {
        let root = try SecureDirectoryHandle.openExactPrivate(rootURL, deadline: deadline)
        defer { root.close() }
        var metadata = stat()
        guard Darwin.fstat(root.descriptor, &metadata) == 0 else {
            throw DeviceAttestationError.namespaceChanged
        }
        let receipt = try root.readExactRegular(
            named: receiptLeafName,
            maximumBytes: maximumReceiptBytes,
            deadline: deadline
        )
        let record = HarnessHomeAttestationRecord(
            canonicalPath: recordURL.standardizedFileURL.path,
            leafName: recordURL.lastPathComponent,
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            mode: UInt16(metadata.st_mode & 0o7777),
            privacyEpoch: privacyEpoch,
            receiptSHA256: Data(SHA256.hash(data: receipt)).hex
        )
        return try retainedCapability(record: record, root: root)
    }

    private static func verifiedCapability(
        _ record: HarnessHomeAttestationRecord,
        rootURL: URL,
        receiptLeafName: String,
        privacyEpoch: UInt64,
        deadline: CheckedDeadline
    ) throws -> HarnessHomeAttestationCapability {
        try verifiedCapability(
            record,
            rootURL: rootURL,
            recordURL: rootURL,
            receiptLeafName: receiptLeafName,
            privacyEpoch: privacyEpoch,
            deadline: deadline
        )
    }

    private static func verifiedCapability(
        _ record: HarnessHomeAttestationRecord,
        rootURL: URL,
        recordURL: URL,
        receiptLeafName: String,
        privacyEpoch: UInt64,
        deadline: CheckedDeadline
    ) throws -> HarnessHomeAttestationCapability {
        try validateExpected(record, rootURL: recordURL, privacyEpoch: privacyEpoch)
        let root = try SecureDirectoryHandle.openExactPrivate(rootURL, deadline: deadline)
        defer { root.close() }
        var metadata = stat()
        guard Darwin.fstat(root.descriptor, &metadata) == 0,
              record.device == UInt64(truncatingIfNeeded: metadata.st_dev),
              record.inode == UInt64(truncatingIfNeeded: metadata.st_ino),
              record.owner == metadata.st_uid,
              record.mode == UInt16(metadata.st_mode & 0o7777) else {
            throw DeviceAttestationError.namespaceChanged
        }
        let receipt = try root.readExactRegular(
            named: receiptLeafName,
            maximumBytes: maximumReceiptBytes,
            deadline: deadline
        )
        let digest = Data(SHA256.hash(data: receipt)).hex
        guard constantTimeEqual(Data(record.receiptSHA256.utf8), Data(digest.utf8)) else {
            throw DeviceAttestationError.namespaceChanged
        }
        return try retainedCapability(record: record, root: root)
    }

    private static func retainedCapability(
        record: HarnessHomeAttestationRecord,
        root: SecureDirectoryHandle
    ) throws -> HarnessHomeAttestationCapability {
        let duplicate = Darwin.fcntl(root.descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else { throw DeviceAttestationError.namespaceChanged }
        var source = stat()
        var copied = stat()
        guard Darwin.fstat(root.descriptor, &source) == 0,
              Darwin.fstat(duplicate, &copied) == 0,
              sameIdentity(source, copied) else {
            Darwin.close(duplicate)
            throw DeviceAttestationError.namespaceChanged
        }
        return HarnessHomeAttestationCapability(record: record, descriptor: duplicate)
    }

    private static func validateInput(rootURL: URL, receiptLeafName: String) throws {
        let standardized = rootURL.standardizedFileURL
        guard rootURL.isFileURL,
              rootURL.path == standardized.path,
              rootURL.path.hasPrefix("/"),
              validLeaf(rootURL.lastPathComponent),
              validLeaf(receiptLeafName) else {
            throw DeviceAttestationError.invalidConfiguration
        }
    }

    private static func validateExpected(
        _ record: HarnessHomeAttestationRecord,
        rootURL: URL,
        privacyEpoch: UInt64
    ) throws {
        guard record.canonicalPath == rootURL.standardizedFileURL.path,
              record.leafName == rootURL.lastPathComponent,
              record.privacyEpoch == privacyEpoch else {
            throw DeviceAttestationError.namespaceChanged
        }
    }

    private static func decode(
        _ bytes: Data,
        verifier: DeviceAttestationVerifier,
        domain: String
    ) throws -> HarnessHomeAttestationRecord {
        let payload = try verifier.verify(
            DeviceAttestationSignedEnvelope(encoded: bytes),
            expectedDomain: domain
        )
        return try HarnessHomeAttestationRecord.decodeExact(payload)
    }

    private static func decodeRotation(
        _ bytes: Data,
        verifier: DeviceAttestationVerifier,
        domain: String
    ) throws -> HarnessHomeAttestationRotationRecord {
        let payload = try verifier.verify(
            DeviceAttestationSignedEnvelope(encoded: bytes),
            expectedDomain: domain
        )
        return try HarnessHomeAttestationRotationRecord.decodeExact(payload)
    }

    private static func decodeRotationIntent(
        _ bytes: Data,
        verifier: DeviceAttestationVerifier
    ) throws -> HarnessHomeAttestationRotationIntent {
        let payload = try verifier.verify(
            DeviceAttestationSignedEnvelope(encoded: bytes),
            expectedDomain: rotationIntentDomain
        )
        return try HarnessHomeAttestationRotationIntent.decodeExact(payload)
    }

    private static func validateRotationIntent(
        _ record: HarnessHomeAttestationRotationRecord,
        operationID: UUID,
        choice: HarnessHomeAttestationRecoveryChoice,
        sourceURL: URL,
        destinationURL: URL,
        targetPrivacyEpoch: UInt64
    ) throws {
        guard record.operationID == operationID,
              record.choice == choice,
              record.sourceCanonicalPath == sourceURL.standardizedFileURL.path,
              record.sourceLeafName == sourceURL.lastPathComponent,
              record.destinationCanonicalPath == destinationURL.standardizedFileURL.path,
              record.destinationLeafName == destinationURL.lastPathComponent,
              record.replacementRecord.privacyEpoch == targetPrivacyEpoch else {
            throw DeviceAttestationError.namespaceChanged
        }
    }

    private static func validateRotationIntent(
        _ intent: HarnessHomeAttestationRotationIntent,
        operationID: UUID,
        choice: HarnessHomeAttestationRecoveryChoice,
        sourceURL: URL,
        destinationURL: URL,
        targetPrivacyEpoch: UInt64
    ) throws {
        guard intent.operationID == operationID,
              intent.choice == choice,
              intent.sourceCanonicalPath == sourceURL.standardizedFileURL.path,
              intent.sourceLeafName == sourceURL.lastPathComponent,
              intent.destinationCanonicalPath == destinationURL.standardizedFileURL.path,
              intent.destinationLeafName == destinationURL.lastPathComponent,
              intent.targetPrivacyEpoch == targetPrivacyEpoch else {
            throw DeviceAttestationError.namespaceChanged
        }
    }

    private static func validateStagedIdentity(
        _ intent: HarnessHomeAttestationRotationIntent,
        stagedRootURL: URL,
        deadline: CheckedDeadline
    ) throws {
        let staged = try SecureDirectoryHandle.openExactPrivate(stagedRootURL, deadline: deadline)
        defer { staged.close() }
        var metadata = stat()
        guard Darwin.fstat(staged.descriptor, &metadata) == 0,
              intent.sourceDevice == UInt64(truncatingIfNeeded: metadata.st_dev),
              intent.sourceInode == UInt64(truncatingIfNeeded: metadata.st_ino),
              intent.sourceOwner == metadata.st_uid,
              intent.sourceMode == UInt16(metadata.st_mode & 0o7777) else {
            throw DeviceAttestationError.namespaceChanged
        }
    }

    private static func revalidateRetainedDescriptor(
        _ capability: HarnessHomeAttestationCapability,
        receiptLeafName: String,
        deadline: CheckedDeadline
    ) throws {
        try capability.withBorrowedDescriptor { descriptor in
            try deadline.check()
            var metadata = stat()
            guard Darwin.fstat(descriptor, &metadata) == 0,
                  capability.record.device == UInt64(truncatingIfNeeded: metadata.st_dev),
                  capability.record.inode == UInt64(truncatingIfNeeded: metadata.st_ino),
                  capability.record.owner == metadata.st_uid,
                  capability.record.mode == UInt16(metadata.st_mode & 0o7777) else {
                throw DeviceAttestationError.namespaceChanged
            }
            let receipt = try readExactRegular(
                beneath: descriptor,
                named: receiptLeafName,
                maximumBytes: maximumReceiptBytes,
                deadline: deadline
            )
            let digest = Data(SHA256.hash(data: receipt)).hex
            guard constantTimeEqual(
                Data(capability.record.receiptSHA256.utf8),
                Data(digest.utf8)
            ) else {
                throw DeviceAttestationError.namespaceChanged
            }
        }
    }

    private static func readExactRegular(
        beneath descriptor: Int32,
        named name: String,
        maximumBytes: Int,
        deadline: CheckedDeadline
    ) throws -> Data {
        guard validLeaf(name) else { throw DeviceAttestationError.invalidConfiguration }
        try deadline.check()
        let file = name.withCString {
            openat(descriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard file >= 0 else { throw DeviceAttestationError.namespaceChanged }
        defer { Darwin.close(file) }
        var before = stat()
        guard Darwin.fstat(file, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_mode & 0o077 == 0,
              before.st_nlink == 1,
              before.st_size >= 0,
              before.st_size <= maximumBytes,
              hasNoExtendedACL(file) else {
            throw DeviceAttestationError.namespaceChanged
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: min(8_192, maximumBytes + 1))
        while true {
            try deadline.check()
            let count = Darwin.read(file, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw DeviceAttestationError.namespaceChanged
            }
            guard count <= maximumBytes - data.count else {
                throw DeviceAttestationError.namespaceChanged
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard Darwin.fstat(file, &after) == 0,
              sameIdentity(before, after),
              after.st_size == data.count else {
            throw DeviceAttestationError.namespaceChanged
        }
        return data
    }

    private static func optionalDataEqual(_ lhs: Data?, _ rhs: Data?) -> Bool {
        switch (lhs, rhs) {
        case (nil, nil): return true
        case (.some(let lhs), .some(let rhs)): return constantTimeEqual(lhs, rhs)
        default: return false
        }
    }

    private static func digest(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).hex
    }

    private static func previousCurrentName(_ operationID: UUID) -> String {
        ".harness-home.previous-\(operationID.uuidString.lowercased())"
    }

    private static func rotationCompletedName(_ operationID: UUID) -> String {
        ".harness-home.rotation-\(operationID.uuidString.lowercased()).completed"
    }

    private func write(
        _ record: HarnessHomeAttestationRecord,
        named name: String,
        domain: String,
        deadline: CheckedDeadline
    ) throws {
        let envelope = try authority.sign(payload: record.encoded(), domain: domain)
        try authority.control.publishNewFile(envelope.encoded, named: name, deadline: deadline)
    }

    private func writeRotation(
        _ record: HarnessHomeAttestationRotationRecord,
        named name: String,
        domain: String,
        deadline: CheckedDeadline
    ) throws {
        let envelope = try authority.sign(payload: record.encoded(), domain: domain)
        try authority.control.publishNewFile(envelope.encoded, named: name, deadline: deadline)
    }

    private func interrupt(_ phase: HarnessHomeAttestationPublicationPhase) throws {
        if interruption?(phase) == true {
            throw DeviceAttestationError.harnessHomeInjectedInterruption(phase)
        }
    }

    private func interruptRotation(_ phase: HarnessHomeAttestationRotationPhase) throws {
        if rotationInterruption?(phase) == true {
            throw DeviceAttestationError.harnessHomeRotationInjectedInterruption(phase)
        }
    }
}

public struct ProviderHistoryNamespaceMarker: Equatable, Sendable {
    public enum State: String, Sendable { case prepared, current }

    public let state: State
    public let canonicalPath: String
    public let leafName: String
    public let sourceCanonicalPath: String
    public let sourceLeafName: String
    public let destinationCanonicalPath: String
    public let destinationLeafName: String
    public let namespaceName: String
    public let device: UInt64
    public let inode: UInt64
    public let owner: UInt32
    public let mode: UInt16
    public let privacyEpoch: UInt64
    public let receiptSHA256: String

    fileprivate func encoded() throws -> Data {
        let object: [String: Any] = [
            "canonicalPath": canonicalPath,
            "destinationCanonicalPath": destinationCanonicalPath,
            "destinationLeafName": destinationLeafName,
            "device": String(device),
            "inode": String(inode),
            "leafName": leafName,
            "mode": String(mode),
            "namespaceName": namespaceName,
            "owner": String(owner),
            "privacyEpoch": String(privacyEpoch),
            "receiptSHA256": receiptSHA256,
            "sourceCanonicalPath": sourceCanonicalPath,
            "sourceLeafName": sourceLeafName,
            "state": state.rawValue,
            "version": 1
        ]
        do { return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
        catch { throw DeviceAttestationError.malformedMarker }
    }

    fileprivate static func decodeExact(_ data: Data) throws -> Self {
        guard data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Set([
                "canonicalPath", "destinationCanonicalPath", "destinationLeafName",
                "device", "inode", "leafName", "mode",
                "namespaceName", "owner", "privacyEpoch", "receiptSHA256",
                "sourceCanonicalPath", "sourceLeafName", "state", "version"
              ]),
              exactInteger(dictionary["version"]) == 1,
              let stateRaw = dictionary["state"] as? String,
              let state = State(rawValue: stateRaw),
              let canonicalPath = dictionary["canonicalPath"] as? String,
              canonicalPath.hasPrefix("/"),
              canonicalPath == URL(fileURLWithPath: canonicalPath).standardizedFileURL.path,
              let leafName = dictionary["leafName"] as? String,
              validLeaf(leafName),
              pathHasLeaf(canonicalPath, leafName),
              let sourceCanonicalPath = dictionary["sourceCanonicalPath"] as? String,
              let sourceLeafName = dictionary["sourceLeafName"] as? String,
              validCanonicalPath(sourceCanonicalPath, leaf: sourceLeafName),
              let destinationCanonicalPath = dictionary["destinationCanonicalPath"] as? String,
              let destinationLeafName = dictionary["destinationLeafName"] as? String,
              validCanonicalPath(destinationCanonicalPath, leaf: destinationLeafName),
              (state == .prepared && canonicalPath == sourceCanonicalPath && leafName == sourceLeafName
                || state == .current && canonicalPath == destinationCanonicalPath && leafName == destinationLeafName),
              let namespaceName = dictionary["namespaceName"] as? String,
              validNamespace(namespaceName),
              let deviceString = dictionary["device"] as? String,
              let device = parseCanonicalUInt64(deviceString),
              let inodeString = dictionary["inode"] as? String,
              let inode = parseCanonicalUInt64(inodeString),
              let ownerString = dictionary["owner"] as? String,
              let owner64 = parseCanonicalUInt64(ownerString),
              let owner = UInt32(exactly: owner64),
              let modeString = dictionary["mode"] as? String,
              let mode64 = parseCanonicalUInt64(modeString),
              let mode = UInt16(exactly: mode64),
              mode & ~UInt16(0o7777) == 0,
              let epochString = dictionary["privacyEpoch"] as? String,
              let epoch = parseCanonicalUInt64(epochString),
              let digest = dictionary["receiptSHA256"] as? String,
              isLowerHexDigest(digest) else {
            throw DeviceAttestationError.malformedMarker
        }
        let marker = Self(
            state: state,
            canonicalPath: canonicalPath,
            leafName: leafName,
            sourceCanonicalPath: sourceCanonicalPath,
            sourceLeafName: sourceLeafName,
            destinationCanonicalPath: destinationCanonicalPath,
            destinationLeafName: destinationLeafName,
            namespaceName: namespaceName,
            device: device,
            inode: inode,
            owner: owner,
            mode: mode,
            privacyEpoch: epoch,
            receiptSHA256: digest
        )
        guard try marker.encoded() == data else { throw DeviceAttestationError.malformedMarker }
        return marker
    }
}

public enum ProviderHistoryNamespaceBackgroundState: Equatable, Sendable {
    case absent
    case foregroundRequired(ProviderHistoryNamespaceMarker)
    case current(ProviderHistoryNamespaceMarker)
}

/// Signed two-record publication for moving one opaque namespace root.
/// No operation in this type enumerates or opens a child of that root.
public final class ProviderHistoryNamespaceMarkerStore: @unchecked Sendable {
    public static let preparedDomain = "com.fulmar.device-attestation/v1/provider-history-namespace/prepared"
    public static let currentDomain = "com.fulmar.device-attestation/v1/provider-history-namespace/current"

    public struct Publication: Sendable {
        public let sourceParent: URL
        public let sourceLeaf: String
        public let destinationParent: URL
        public let destinationLeaf: String
        public let namespaceName: String
        public let privacyEpoch: UInt64
        public let receipt: Data
        public let operationDuration: TimeInterval

        public init(
            sourceParent: URL,
            sourceLeaf: String,
            destinationParent: URL,
            destinationLeaf: String,
            namespaceName: String,
            privacyEpoch: UInt64,
            receipt: Data,
            operationDuration: TimeInterval = 10
        ) {
            self.sourceParent = sourceParent
            self.sourceLeaf = sourceLeaf
            self.destinationParent = destinationParent
            self.destinationLeaf = destinationLeaf
            self.namespaceName = namespaceName
            self.privacyEpoch = privacyEpoch
            self.receipt = receipt
            self.operationDuration = operationDuration
        }
    }

    public struct BackgroundExpectation: Sendable {
        public let namespaceName: String
        public let expectedURL: URL
        public let expectedPrivacyEpoch: UInt64
        public let expectedReceipt: Data

        public init(
            namespaceName: String,
            expectedURL: URL,
            expectedPrivacyEpoch: UInt64,
            expectedReceipt: Data
        ) {
            self.namespaceName = namespaceName
            self.expectedURL = expectedURL
            self.expectedPrivacyEpoch = expectedPrivacyEpoch
            self.expectedReceipt = expectedReceipt
        }
    }

    private let authority: DeviceAttestationAuthority
    private let interruption: (@Sendable (ProviderHistoryNamespacePublicationPhase) -> Bool)?

    @_spi(Testing) public init(
        authority: DeviceAttestationAuthority,
        interruption: (@Sendable (ProviderHistoryNamespacePublicationPhase) -> Bool)? = nil
    ) {
        self.authority = authority
        self.interruption = interruption
    }

    /// Background probe. A `.prepared` record always requires foreground recovery,
    /// including the crash window where a matching `.current` was written first.
    public static func backgroundState(
        namespaceName: String,
        expectedURL: URL,
        expectedPrivacyEpoch: UInt64,
        expectedReceipt: Data,
        configuration: DeviceAttestationAuthority.Configuration,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> ProviderHistoryNamespaceBackgroundState {
        let results = try backgroundStates(
            [.init(
                namespaceName: namespaceName,
                expectedURL: expectedURL,
                expectedPrivacyEpoch: expectedPrivacyEpoch,
                expectedReceipt: expectedReceipt
            )],
            configuration: configuration,
            keyStore: keyStore
        )
        guard let result = results[namespaceName] else { throw DeviceAttestationError.invalidConfiguration }
        return result
    }

    /// Batches independent namespace slots under one bounded public-anchor lookup.
    /// If every requested slot is absent, no Keychain query is issued.
    public static func backgroundStates(
        _ expectations: [BackgroundExpectation],
        configuration: DeviceAttestationAuthority.Configuration,
        keyStore: any DeviceAttestationKeyStore
    ) throws -> [String: ProviderHistoryNamespaceBackgroundState] {
        guard !expectations.isEmpty, expectations.count <= 32,
              Set(expectations.map(\.namespaceName)).count == expectations.count,
              expectations.allSatisfy({
                validNamespace($0.namespaceName) && $0.expectedURL.isFileURL
                    && $0.expectedReceipt.count <= 1_048_576
              }) else {
            throw DeviceAttestationError.invalidConfiguration
        }
        let deadline = try CheckedDeadline(duration: configuration.operationDuration)
        guard let control = try DeviceAttestationControlDirectory.openExistingIfPresent(
            beneath: configuration.controlParent,
            deadline: deadline
        ) else { return Dictionary(uniqueKeysWithValues: expectations.map { ($0.namespaceName, .absent) }) }
        defer { control.close() }
        var slots: [(BackgroundExpectation, Data?, Data?)] = []
        var anyMarker = false
        for expectation in expectations {
            let names = markerNames(expectation.namespaceName)
            let prepared = try control.readOptionalFile(named: names.prepared, maximumBytes: 32_768, deadline: deadline)
            let current = try control.readOptionalFile(named: names.current, maximumBytes: 32_768, deadline: deadline)
            anyMarker = anyMarker || prepared != nil || current != nil
            slots.append((expectation, prepared, current))
        }
        guard anyMarker else {
            return Dictionary(uniqueKeysWithValues: expectations.map { ($0.namespaceName, .absent) })
        }
        let verifier = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: configuration, keyStore: keyStore)
        var results: [String: ProviderHistoryNamespaceBackgroundState] = [:]
        for (expectation, preparedBytes, currentBytes) in slots {
            let expectedPath = expectation.expectedURL.standardizedFileURL.path
            let expectedReceiptDigest = Data(SHA256.hash(data: expectation.expectedReceipt)).hex
            if let envelope = preparedBytes {
                let payload = try verifier.verify(
                    DeviceAttestationSignedEnvelope(encoded: envelope), expectedDomain: preparedDomain
                )
                let marker = try ProviderHistoryNamespaceMarker.decodeExact(payload)
                guard marker.state == .prepared,
                      marker.namespaceName == expectation.namespaceName,
                      marker.privacyEpoch == expectation.expectedPrivacyEpoch,
                      constantTimeEqual(Data(marker.receiptSHA256.utf8), Data(expectedReceiptDigest.utf8)),
                      expectedPath == marker.sourceCanonicalPath || expectedPath == marker.destinationCanonicalPath else {
                    throw DeviceAttestationError.namespaceChanged
                }
                results[expectation.namespaceName] = .foregroundRequired(marker)
                continue
            }
            if let envelope = currentBytes {
                let payload = try verifier.verify(
                    DeviceAttestationSignedEnvelope(encoded: envelope), expectedDomain: currentDomain
                )
                let marker = try ProviderHistoryNamespaceMarker.decodeExact(payload)
                guard marker.state == .current,
                      marker.namespaceName == expectation.namespaceName,
                      marker.privacyEpoch == expectation.expectedPrivacyEpoch,
                      constantTimeEqual(Data(marker.receiptSHA256.utf8), Data(expectedReceiptDigest.utf8)),
                      marker.canonicalPath == expectedPath else {
                    throw DeviceAttestationError.namespaceChanged
                }
                try validateLive(marker: marker, deadline: deadline)
                results[expectation.namespaceName] = .current(marker)
                continue
            }
            results[expectation.namespaceName] = .absent
        }
        return results
    }

    @discardableResult
    public func publish(_ publication: Publication) throws -> ProviderHistoryNamespaceMarker {
        guard validLeaf(publication.sourceLeaf),
              validLeaf(publication.destinationLeaf),
              validNamespace(publication.namespaceName),
              publication.receipt.count <= 1_048_576 else {
            throw DeviceAttestationError.invalidConfiguration
        }
        let deadline = try CheckedDeadline(duration: publication.operationDuration)
        let source = try SecureDirectoryHandle.openExactPrivate(publication.sourceParent, deadline: deadline)
        defer { source.close() }
        let destination = try SecureDirectoryHandle.openExactPrivate(publication.destinationParent, deadline: deadline)
        defer { destination.close() }
        try deadline.check()

        let sourceMetadata = try source.statOpaqueRoot(named: publication.sourceLeaf)
        guard sourceMetadata.st_uid == geteuid(),
              sourceMetadata.st_mode & 0o077 == 0 else {
            throw DeviceAttestationError.namespaceChanged
        }
        var destinationMetadata = stat()
        if publication.destinationLeaf.withCString({
            fstatat(destination.descriptor, $0, &destinationMetadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            throw DeviceAttestationError.destinationExists
        }
        guard errno == ENOENT else { throw DeviceAttestationError.unsafeControlPath }

        let digest = Data(SHA256.hash(data: publication.receipt)).hex
        let sourcePath = publication.sourceParent.standardizedFileURL
            .appendingPathComponent(publication.sourceLeaf).standardizedFileURL.path
        let destinationPath = publication.destinationParent.standardizedFileURL
            .appendingPathComponent(publication.destinationLeaf).standardizedFileURL.path
        let prepared = marker(
            state: .prepared,
            sourcePath: sourcePath,
            sourceLeaf: publication.sourceLeaf,
            destinationPath: destinationPath,
            destinationLeaf: publication.destinationLeaf,
            namespace: publication.namespaceName,
            metadata: sourceMetadata,
            epoch: publication.privacyEpoch,
            digest: digest
        )
        let names = Self.markerNames(publication.namespaceName)
        if try authority.control.readOptionalFile(named: names.prepared, maximumBytes: 32_768, deadline: deadline) != nil
            || authority.control.readOptionalFile(named: names.current, maximumBytes: 32_768, deadline: deadline) != nil {
            throw DeviceAttestationError.foregroundRequired
        }
        try write(marker: prepared, named: names.prepared, domain: Self.preparedDomain, replace: false, deadline: deadline)
        try interrupt(.preparedWritten)

        let renameStatus = publication.sourceLeaf.withCString { sourceName in
            publication.destinationLeaf.withCString { destinationName in
                renameat(source.descriptor, sourceName, destination.descriptor, destinationName)
            }
        }
        guard renameStatus == 0 else { throw DeviceAttestationError.renameFailed(errno) }
        guard fsync(source.descriptor) == 0,
              source.descriptor == destination.descriptor || fsync(destination.descriptor) == 0 else {
            throw DeviceAttestationError.unsafeControlPath
        }
        try deadline.check()
        let moved = try destination.statOpaqueRoot(named: publication.destinationLeaf)
        guard sameIdentity(sourceMetadata, moved) else { throw DeviceAttestationError.namespaceChanged }
        try interrupt(.rootRenamedAndSynced)

        let current = marker(
            state: .current,
            sourcePath: sourcePath,
            sourceLeaf: publication.sourceLeaf,
            destinationPath: destinationPath,
            destinationLeaf: publication.destinationLeaf,
            namespace: publication.namespaceName,
            metadata: moved,
            epoch: publication.privacyEpoch,
            digest: digest
        )
        try write(marker: current, named: names.current, domain: Self.currentDomain, replace: false, deadline: deadline)
        try interrupt(.currentWritten)
        try authority.control.removeFileIfPresent(named: names.prepared, deadline: deadline)
        return current
    }

    /// Foreground-only recovery for every interruption window. It never replaces a
    /// collision: exactly one identity-bound source or destination must be present.
    public func reconcilePrepared(namespaceName: String) throws -> ProviderHistoryNamespaceMarker {
        guard validNamespace(namespaceName) else { throw DeviceAttestationError.invalidConfiguration }
        let deadline = try CheckedDeadline(duration: 5)
        let names = Self.markerNames(namespaceName)
        guard let preparedBytes = try authority.control.readOptionalFile(named: names.prepared, maximumBytes: 32_768, deadline: deadline) else {
            throw DeviceAttestationError.foregroundRequired
        }
        let currentBytes = try authority.control.readOptionalFile(named: names.current, maximumBytes: 32_768, deadline: deadline)
        let verifier = authority.verifier()
        let preparedPayload = try verifier.verify(
            DeviceAttestationSignedEnvelope(encoded: preparedBytes), expectedDomain: Self.preparedDomain
        )
        let prepared = try ProviderHistoryNamespaceMarker.decodeExact(preparedPayload)
        guard prepared.state == .prepared,
              prepared.namespaceName == namespaceName else {
            throw DeviceAttestationError.namespaceChanged
        }

        let sourceURL = URL(fileURLWithPath: prepared.sourceCanonicalPath)
        let destinationURL = URL(fileURLWithPath: prepared.destinationCanonicalPath)
        let source = try SecureDirectoryHandle.openExactPrivate(sourceURL.deletingLastPathComponent(), deadline: deadline)
        defer { source.close() }
        let destination = try SecureDirectoryHandle.openExactPrivate(destinationURL.deletingLastPathComponent(), deadline: deadline)
        defer { destination.close() }
        let sourceMetadata = try source.statOpaqueRootIfPresent(named: prepared.sourceLeafName)
        let destinationMetadata = try destination.statOpaqueRootIfPresent(named: prepared.destinationLeafName)

        if let currentBytes {
            let currentPayload = try verifier.verify(
                DeviceAttestationSignedEnvelope(encoded: currentBytes), expectedDomain: Self.currentDomain
            )
            let current = try ProviderHistoryNamespaceMarker.decodeExact(currentPayload)
            guard markersDescribeSameMove(prepared, current), sourceMetadata == nil,
                  let destinationMetadata, markerIdentityMatches(current, destinationMetadata) else {
                throw DeviceAttestationError.namespaceChanged
            }
            try authority.control.removeFileIfPresent(named: names.prepared, deadline: deadline)
            return current
        }

        if let sourceMetadata, destinationMetadata == nil, markerIdentityMatches(prepared, sourceMetadata) {
            let status = prepared.sourceLeafName.withCString { sourceName in
                prepared.destinationLeafName.withCString { destinationName in
                    renameat(source.descriptor, sourceName, destination.descriptor, destinationName)
                }
            }
            guard status == 0, fsync(source.descriptor) == 0,
                  source.descriptor == destination.descriptor || fsync(destination.descriptor) == 0 else {
                throw DeviceAttestationError.renameFailed(errno)
            }
        } else {
            guard sourceMetadata == nil,
                  let destinationMetadata,
                  markerIdentityMatches(prepared, destinationMetadata) else {
                throw DeviceAttestationError.namespaceChanged
            }
        }
        guard let moved = try destination.statOpaqueRootIfPresent(named: prepared.destinationLeafName),
              markerIdentityMatches(prepared, moved) else { throw DeviceAttestationError.namespaceChanged }
        let current = ProviderHistoryNamespaceMarker(
            state: .current,
            canonicalPath: prepared.destinationCanonicalPath,
            leafName: prepared.destinationLeafName,
            sourceCanonicalPath: prepared.sourceCanonicalPath,
            sourceLeafName: prepared.sourceLeafName,
            destinationCanonicalPath: prepared.destinationCanonicalPath,
            destinationLeafName: prepared.destinationLeafName,
            namespaceName: prepared.namespaceName,
            device: prepared.device, inode: prepared.inode, owner: prepared.owner, mode: prepared.mode,
            privacyEpoch: prepared.privacyEpoch, receiptSHA256: prepared.receiptSHA256
        )
        try write(marker: current, named: names.current, domain: Self.currentDomain, replace: false, deadline: deadline)
        try authority.control.removeFileIfPresent(named: names.prepared, deadline: deadline)
        return current
    }

    private func marker(
        state: ProviderHistoryNamespaceMarker.State,
        sourcePath: String,
        sourceLeaf: String,
        destinationPath: String,
        destinationLeaf: String,
        namespace: String,
        metadata: stat,
        epoch: UInt64,
        digest: String
    ) -> ProviderHistoryNamespaceMarker {
        return ProviderHistoryNamespaceMarker(
            state: state,
            canonicalPath: state == .prepared ? sourcePath : destinationPath,
            leafName: state == .prepared ? sourceLeaf : destinationLeaf,
            sourceCanonicalPath: sourcePath,
            sourceLeafName: sourceLeaf,
            destinationCanonicalPath: destinationPath,
            destinationLeafName: destinationLeaf,
            namespaceName: namespace,
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            mode: UInt16(metadata.st_mode & 0o7777),
            privacyEpoch: epoch,
            receiptSHA256: digest
        )
    }

    private func write(
        marker: ProviderHistoryNamespaceMarker,
        named name: String,
        domain: String,
        replace: Bool,
        deadline: CheckedDeadline
    ) throws {
        let envelope = try authority.sign(payload: marker.encoded(), domain: domain)
        if replace {
            try authority.control.atomicReplaceFile(envelope.encoded, named: name, deadline: deadline)
        } else {
            try authority.control.publishNewFile(envelope.encoded, named: name, deadline: deadline)
        }
    }

    private static func markerNames(_ namespace: String) -> (prepared: String, current: String) {
        let slot = Data(SHA256.hash(data: Data(namespace.utf8))).hex
        return (".namespace-\(slot).prepared", ".namespace-\(slot).current")
    }

    private static func validateLive(marker: ProviderHistoryNamespaceMarker, deadline: CheckedDeadline) throws {
        let url = URL(fileURLWithPath: marker.canonicalPath)
        let parent = try SecureDirectoryHandle.openExactPrivate(url.deletingLastPathComponent(), deadline: deadline)
        defer { parent.close() }
        let metadata = try parent.statOpaqueRoot(named: marker.leafName)
        guard markerIdentityMatches(marker, metadata) else { throw DeviceAttestationError.namespaceChanged }
    }

    private func interrupt(_ phase: ProviderHistoryNamespacePublicationPhase) throws {
        if interruption?(phase) == true { throw DeviceAttestationError.injectedInterruption(phase) }
    }
}

// MARK: - Descriptor-bound storage

private final class DeviceAttestationControlDirectory: @unchecked Sendable {
    private let lock = NSLock()
    private var descriptorStorage: Int32
    var descriptor: Int32 { lock.withLock { descriptorStorage } }

    private init(descriptor: Int32) { descriptorStorage = descriptor }

    static func openOrCreate(beneath parent: URL, deadline: CheckedDeadline) throws -> Self {
        let parentFD = try openAbsoluteDirectoryNoSymlink(parent, deadline: deadline)
        defer { Darwin.close(parentFD) }
        let control = try openOrCreatePrivateChild(parent: parentFD, name: ".FulmarControl")
        defer { Darwin.close(control) }
        let attestation = try openOrCreatePrivateChild(parent: control, name: "DeviceAttestation")
        return Self(descriptor: attestation)
    }

    static func openExisting(beneath parent: URL, deadline: CheckedDeadline) throws -> Self {
        let parentFD = try openAbsoluteDirectoryNoSymlink(parent, deadline: deadline)
        defer { Darwin.close(parentFD) }
        let control = try openPrivateChild(parent: parentFD, name: ".FulmarControl")
        defer { Darwin.close(control) }
        let attestation = try openPrivateChild(parent: control, name: "DeviceAttestation")
        return Self(descriptor: attestation)
    }

    static func openExistingIfPresent(beneath parent: URL, deadline: CheckedDeadline) throws -> Self? {
        let parentFD = try openAbsoluteDirectoryNoSymlink(parent, deadline: deadline)
        defer { Darwin.close(parentFD) }
        guard let control = try openPrivateChildIfPresent(parent: parentFD, name: ".FulmarControl") else {
            return nil
        }
        defer { Darwin.close(control) }
        guard let attestation = try openPrivateChildIfPresent(parent: control, name: "DeviceAttestation") else {
            return nil
        }
        return Self(descriptor: attestation)
    }

    func close() {
        lock.withLock {
            if descriptorStorage >= 0 {
                Darwin.close(descriptorStorage)
                descriptorStorage = -1
            }
        }
    }

    func readOptionalFile(named name: String, exactBytes: Int, deadline: CheckedDeadline) throws -> Data? {
        let value = try readOptionalFile(named: name, maximumBytes: exactBytes, deadline: deadline)
        if let value, value.count != exactBytes {
            throw DeviceAttestationError.unsafeControlFile
        }
        return value
    }

    func readOptionalFile(named name: String, maximumBytes: Int, deadline: CheckedDeadline) throws -> Data? {
        guard validLeaf(name), maximumBytes > 0, maximumBytes <= 1_048_576 else {
            throw DeviceAttestationError.invalidConfiguration
        }
        try deadline.check()
        let fd = name.withCString { openat(descriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) }
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw DeviceAttestationError.unsafeControlFile
        }
        defer { Darwin.close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_mode & 0o177 == 0,
              before.st_nlink == 1,
              before.st_size >= 0,
              before.st_size <= maximumBytes,
              hasNoExtendedACL(fd) else {
            throw DeviceAttestationError.unsafeControlFile
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: min(8_192, maximumBytes + 1))
        while true {
            try deadline.check()
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw DeviceAttestationError.unsafeControlFile
            }
            guard data.count <= maximumBytes - count else { throw DeviceAttestationError.unsafeControlFile }
            data.append(buffer, count: count)
        }
        var after = stat()
        var rebound = stat()
        guard fstat(fd, &after) == 0,
              name.withCString({ fstatat(descriptor, $0, &rebound, AT_SYMLINK_NOFOLLOW) }) == 0,
              sameIdentity(before, after), sameIdentity(after, rebound),
              after.st_size == data.count else {
            throw DeviceAttestationError.unsafeControlFile
        }
        return data
    }

    func publishNewFile(_ data: Data, named name: String, deadline: CheckedDeadline) throws {
        try atomicWrite(data, named: name, replace: false, deadline: deadline)
    }

    func atomicReplaceFile(_ data: Data, named name: String, deadline: CheckedDeadline) throws {
        try atomicWrite(data, named: name, replace: true, deadline: deadline)
    }

    func removeFileIfPresent(named name: String, deadline: CheckedDeadline) throws {
        try deadline.check()
        let status = name.withCString { unlinkat(descriptor, $0, 0) }
        if status != 0, errno != ENOENT { throw DeviceAttestationError.unsafeControlFile }
        if status == 0, fsync(descriptor) != 0 { throw DeviceAttestationError.unsafeControlPath }
    }

    private func atomicWrite(_ data: Data, named name: String, replace: Bool, deadline: CheckedDeadline) throws {
        guard validLeaf(name), data.count <= 1_048_576 else { throw DeviceAttestationError.invalidConfiguration }
        try deadline.check()
        if !replace {
            var existing = stat()
            if name.withCString({ fstatat(descriptor, $0, &existing, AT_SYMLINK_NOFOLLOW) }) == 0 {
                throw DeviceAttestationError.unsafeControlFile
            }
            guard errno == ENOENT else { throw DeviceAttestationError.unsafeControlFile }
        }
        let temporary = ".tmp-\(UUID().uuidString.lowercased())"
        let fd = temporary.withCString {
            openat(descriptor, $0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        }
        guard fd >= 0 else { throw DeviceAttestationError.unsafeControlFile }
        var installed = false
        defer {
            Darwin.close(fd)
            if !installed { _ = temporary.withCString { unlinkat(descriptor, $0, 0) } }
        }
        try writeAll(data, to: fd, deadline: deadline)
        guard fsync(fd) == 0 else { throw DeviceAttestationError.unsafeControlFile }
        if !replace {
            var existing = stat()
            if name.withCString({ fstatat(descriptor, $0, &existing, AT_SYMLINK_NOFOLLOW) }) == 0 {
                throw DeviceAttestationError.unsafeControlFile
            }
            guard errno == ENOENT else { throw DeviceAttestationError.unsafeControlFile }
        }
        let status = temporary.withCString { temporaryName in
            name.withCString { destinationName in
                renameat(descriptor, temporaryName, descriptor, destinationName)
            }
        }
        guard status == 0, fsync(descriptor) == 0 else { throw DeviceAttestationError.unsafeControlFile }
        installed = true
    }
}

private final class SecureDirectoryHandle {
    let descriptor: Int32
    private init(_ descriptor: Int32) { self.descriptor = descriptor }
    static func openExactPrivate(_ url: URL, deadline: CheckedDeadline) throws -> Self {
        let descriptor = try openAbsoluteDirectoryNoSymlink(url, deadline: deadline)
        do {
            try validatePrivateDirectory(descriptor)
            return Self(descriptor)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }
    func close() { Darwin.close(descriptor) }
    func statOpaqueRoot(named name: String) throws -> stat {
        var value = stat()
        guard name.withCString({ fstatat(descriptor, $0, &value, AT_SYMLINK_NOFOLLOW) }) == 0,
              value.st_mode & S_IFMT == S_IFDIR,
              value.st_nlink >= 2 else {
            throw DeviceAttestationError.namespaceChanged
        }
        return value
    }
    func statOpaqueRootIfPresent(named name: String) throws -> stat? {
        var value = stat()
        if name.withCString({ fstatat(descriptor, $0, &value, AT_SYMLINK_NOFOLLOW) }) != 0 {
            if errno == ENOENT { return nil }
            throw DeviceAttestationError.namespaceChanged
        }
        guard value.st_mode & S_IFMT == S_IFDIR, value.st_nlink >= 2 else {
            throw DeviceAttestationError.namespaceChanged
        }
        return value
    }

    func readExactRegular(
        named name: String,
        maximumBytes: Int,
        deadline: CheckedDeadline
    ) throws -> Data {
        guard validLeaf(name), maximumBytes > 0, maximumBytes <= 1_048_576 else {
            throw DeviceAttestationError.invalidConfiguration
        }
        try deadline.check()
        let file = name.withCString {
            openat(descriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard file >= 0 else { throw DeviceAttestationError.namespaceChanged }
        defer { Darwin.close(file) }
        var before = stat()
        guard Darwin.fstat(file, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == geteuid(),
              before.st_mode & 0o077 == 0,
              before.st_nlink == 1,
              before.st_size >= 0,
              before.st_size <= maximumBytes,
              hasNoExtendedACL(file) else {
            throw DeviceAttestationError.namespaceChanged
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: min(8_192, maximumBytes + 1))
        while true {
            try deadline.check()
            let count = Darwin.read(file, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw DeviceAttestationError.namespaceChanged
            }
            guard count <= maximumBytes - data.count else {
                throw DeviceAttestationError.namespaceChanged
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        var rebound = stat()
        guard Darwin.fstat(file, &after) == 0,
              name.withCString({ fstatat(descriptor, $0, &rebound, AT_SYMLINK_NOFOLLOW) }) == 0,
              sameIdentity(before, after),
              sameIdentity(after, rebound),
              after.st_size == data.count else {
            throw DeviceAttestationError.namespaceChanged
        }
        return data
    }
}

private struct CheckedDeadline: Sendable {
    let end: UInt64
    init(duration: TimeInterval) throws {
        guard duration.isFinite, duration > 0, duration <= 120 else {
            throw DeviceAttestationError.invalidConfiguration
        }
        let nanosecondsDouble = duration * 1_000_000_000
        guard nanosecondsDouble.isFinite,
              nanosecondsDouble <= Double(UInt64.max),
              let amount = UInt64(exactly: nanosecondsDouble.rounded(.down)) else {
            throw DeviceAttestationError.invalidConfiguration
        }
        let start = DispatchTime.now().uptimeNanoseconds
        let (candidate, overflow) = start.addingReportingOverflow(amount)
        guard !overflow else { throw DeviceAttestationError.invalidConfiguration }
        end = candidate
    }
    func check() throws {
        guard DispatchTime.now().uptimeNanoseconds <= end else {
            throw DeviceAttestationError.deadlineExceeded
        }
    }
}

private func requireStrictDescendant(_ candidate: URL, of parent: URL) throws {
    guard candidate.isFileURL, parent.isFileURL else {
        throw DeviceAttestationError.recoveryAuthorizationInvalid
    }
    let candidatePath = candidate.standardizedFileURL.path
    let parentPath = parent.standardizedFileURL.path
    guard candidatePath == candidate.path,
          parentPath == parent.path,
          candidatePath.hasPrefix(parentPath + "/"),
          candidatePath != parentPath else {
        throw DeviceAttestationError.recoveryAuthorizationInvalid
    }
}

private func opaqueNodeExists(
    beneath parent: URL,
    leaf: String,
    deadline: CheckedDeadline
) throws -> Bool {
    guard validLeaf(leaf) else { throw DeviceAttestationError.invalidConfiguration }
    let descriptor = try openAbsoluteDirectoryNoSymlink(parent, deadline: deadline)
    defer { Darwin.close(descriptor) }
    try deadline.check()
    var metadata = stat()
    if leaf.withCString({ fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW) }) == 0 {
        return true
    }
    if errno == ENOENT { return false }
    throw DeviceAttestationError.unsafeControlPath
}

private func openAbsoluteDirectoryNoSymlink(_ url: URL, deadline: CheckedDeadline) throws -> Int32 {
    guard url.isFileURL else { throw DeviceAttestationError.unsafeControlPath }
    let path = url.standardizedFileURL.path
    guard path.hasPrefix("/"), path == url.path else { throw DeviceAttestationError.unsafeControlPath }
    var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard current >= 0 else { throw DeviceAttestationError.unsafeControlPath }
    do {
        guard ancestorDescriptorIsSafe(current) else { throw DeviceAttestationError.unsafeControlPath }
        for component in path.split(separator: "/").map(String.init) {
            try deadline.check()
            guard validLeaf(component) else { throw DeviceAttestationError.unsafeControlPath }
            let next = component.withCString {
                openat(current, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            }
            guard next >= 0 else { throw DeviceAttestationError.unsafeControlPath }
            guard ancestorDescriptorIsSafe(next) else {
                Darwin.close(next)
                throw DeviceAttestationError.unsafeControlPath
            }
            Darwin.close(current)
            current = next
        }
        return current
    } catch {
        Darwin.close(current)
        throw error
    }
}

private func openOrCreatePrivateChild(parent: Int32, name: String) throws -> Int32 {
    var descriptor = try? openPrivateChild(parent: parent, name: name)
    if descriptor == nil {
        var metadata = stat()
        let exists = name.withCString({ fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW) }) == 0
        guard !exists, errno == ENOENT,
              name.withCString({ mkdirat(parent, $0, 0o700) }) == 0 else {
            throw DeviceAttestationError.unsafeControlPath
        }
        guard fsync(parent) == 0 else { throw DeviceAttestationError.unsafeControlPath }
        descriptor = try openPrivateChild(parent: parent, name: name)
    }
    guard let descriptor else { throw DeviceAttestationError.unsafeControlPath }
    return descriptor
}

private func openPrivateChild(parent: Int32, name: String) throws -> Int32 {
    guard validLeaf(name) else { throw DeviceAttestationError.unsafeControlPath }
    var named = stat()
    guard name.withCString({ fstatat(parent, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
          named.st_mode & S_IFMT == S_IFDIR else {
        throw DeviceAttestationError.unsafeControlPath
    }
    let descriptor = name.withCString {
        openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    }
    guard descriptor >= 0 else { throw DeviceAttestationError.unsafeControlPath }
    do {
        try validatePrivateDirectory(descriptor)
        var opened = stat()
        guard fstat(descriptor, &opened) == 0, sameIdentity(named, opened) else {
            throw DeviceAttestationError.unsafeControlPath
        }
        return descriptor
    } catch {
        Darwin.close(descriptor)
        throw error
    }
}

private func openPrivateChildIfPresent(parent: Int32, name: String) throws -> Int32? {
    var metadata = stat()
    if name.withCString({ fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW) }) != 0 {
        if errno == ENOENT { return nil }
        throw DeviceAttestationError.unsafeControlPath
    }
    return try openPrivateChild(parent: parent, name: name)
}

private func validatePrivateDirectory(_ descriptor: Int32) throws {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o7777 == 0o700,
          hasNoExtendedACL(descriptor) else {
        throw DeviceAttestationError.unsafeControlPath
    }
}

private func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else { return errno == ENOENT }
    _ = acl_free(UnsafeMutableRawPointer(list))
    return false
}

/// macOS gives the standard home/Library/Application Support ancestors one
/// deny-only `everyone/delete` ACE. It grants no access and prevents unlinking;
/// all other extended-ACL shapes on an ancestor are rejected.
private func ancestorACLIsSafe(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else { return errno == ENOENT }
    defer { _ = acl_free(UnsafeMutableRawPointer(list)) }
    var length: ssize_t = 0
    guard let raw = acl_to_text(list, &length), length > 0, length <= 512 else { return false }
    defer { _ = acl_free(UnsafeMutableRawPointer(raw)) }
    let exact = "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete\n"
    return String(cString: raw) == exact
}

private func ancestorDescriptorIsSafe(_ descriptor: Int32) -> Bool {
    var metadata = stat()
    return fstat(descriptor, &metadata) == 0
        && metadata.st_mode & S_IFMT == S_IFDIR
        && (metadata.st_uid == 0 || metadata.st_uid == geteuid())
        && metadata.st_mode & 0o022 == 0
        && ancestorACLIsSafe(descriptor)
}

private func writeAll(_ data: Data, to descriptor: Int32, deadline: CheckedDeadline) throws {
    try data.withUnsafeBytes { bytes in
        var offset = 0
        while offset < bytes.count {
            try deadline.check()
            let count = Darwin.write(descriptor, bytes.baseAddress?.advanced(by: offset), bytes.count - offset)
            if count > 0 { offset += count }
            else if count < 0, errno == EINTR { continue }
            else { throw DeviceAttestationError.unsafeControlFile }
        }
    }
}

private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var value = value.bigEndian
    withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
}

private func exactInteger(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    let result = number.intValue
    return NSNumber(value: result) == number ? result : nil
}

private func parseCanonicalUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty,
          value == "0" || value.first != "0",
          value.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
    return UInt64(value)
}

private func validLeaf(_ value: String) -> Bool {
    !value.isEmpty && value != "." && value != ".." && value.utf8.count <= 255
        && !value.contains("/") && !value.contains("\0")
}

private func validNamespace(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 256 && !value.contains("\0")
}

private func pathHasLeaf(_ path: String, _ leaf: String) -> Bool {
    validLeaf(leaf) && URL(fileURLWithPath: path).lastPathComponent == leaf
}

private func validCanonicalPath(_ path: String, leaf: String) -> Bool {
    path.hasPrefix("/") && path == URL(fileURLWithPath: path).standardizedFileURL.path
        && pathHasLeaf(path, leaf)
}

private func markerIdentityMatches(_ marker: ProviderHistoryNamespaceMarker, _ metadata: stat) -> Bool {
    marker.device == UInt64(truncatingIfNeeded: metadata.st_dev)
        && marker.inode == UInt64(truncatingIfNeeded: metadata.st_ino)
        && marker.owner == metadata.st_uid
        && marker.mode == UInt16(metadata.st_mode & 0o7777)
}

private func markersDescribeSameMove(
    _ prepared: ProviderHistoryNamespaceMarker,
    _ current: ProviderHistoryNamespaceMarker
) -> Bool {
    current.state == .current
        && prepared.sourceCanonicalPath == current.sourceCanonicalPath
        && prepared.sourceLeafName == current.sourceLeafName
        && prepared.destinationCanonicalPath == current.destinationCanonicalPath
        && prepared.destinationLeafName == current.destinationLeafName
        && prepared.namespaceName == current.namespaceName
        && prepared.device == current.device
        && prepared.inode == current.inode
        && prepared.owner == current.owner
        && prepared.mode == current.mode
        && prepared.privacyEpoch == current.privacyEpoch
        && prepared.receiptSHA256 == current.receiptSHA256
}

private func isLowerHexDigest(_ value: String) -> Bool {
    value.utf8.count == 64 && value.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
}

private func sameIdentity(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_uid == rhs.st_uid
        && lhs.st_mode == rhs.st_mode && lhs.st_nlink == rhs.st_nlink
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (a, b) in zip(lhs, rhs) { difference |= a ^ b }
    return difference == 0
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
