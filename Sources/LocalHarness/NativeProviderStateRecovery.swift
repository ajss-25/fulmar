import Darwin
import CryptoKit
import Foundation

enum NativeProviderStateDocument: String, CaseIterable, Hashable, Sendable {
    case modelSettings
    case providerConsent

    fileprivate var defaultsKey: String {
        switch self {
        case .modelSettings: return ModelProviderSettingsStore.settingsKey
        case .providerConsent: return ProviderConsentStore.stateKey
        }
    }

    fileprivate var fileStem: String {
        switch self {
        case .modelSettings: return "model-provider-settings"
        case .providerConsent: return "provider-consent"
        }
    }
}

enum NativeProviderStateFailureKind: Equatable, Sendable {
    case corrupt
    case futureSchema(found: Int, supported: Int)
    case invalidContents
    case invalidStoredType
    case oversized
}

struct NativeProviderStateIssue: Equatable, Sendable {
    let document: NativeProviderStateDocument
    let kind: NativeProviderStateFailureKind
    /// Binds the user's confirmation to the exact bounded stored value without
    /// exposing any document content in UI, diagnostics, or notifications.
    let fingerprint: NativeProviderStateFingerprint
}

struct NativeProviderStateFingerprint: Equatable, Sendable {
    enum Encoding: String, Equatable, Sendable {
        case data
        case binaryPropertyList
    }

    let encoding: Encoding
    let byteCount: Int
    let sha256: String
}

struct NativeProviderStateInspection: Equatable, Sendable {
    let issues: [NativeProviderStateIssue]
    let routeIssue: NativeProviderRouteIssue?

    var requiresRecovery: Bool { !issues.isEmpty || routeIssue != nil }
    var permitsStateReset: Bool { !issues.isEmpty }
    var affectedDocuments: Set<NativeProviderStateDocument> { Set(issues.map(\.document)) }
}

enum NativeProviderRouteIssue: Equatable, Sendable {
    case invalidSelection
    case consentUnavailable
}

struct NativeProviderStateRecoveryReceipt: Equatable, Sendable {
    let recoveryDirectory: URL
    let quarantinedFiles: [NativeProviderStateDocument: URL]
    let resetWithoutRecoveryCopy: Set<NativeProviderStateDocument>
}

struct NativeProviderStateRecoveryArchive: Equatable, Sendable {
    let url: URL
    let byteCount: Int
    let modifiedAt: Date
    let device: UInt64
    let inode: UInt64
    let contentSHA256: String

    fileprivate let modifiedSeconds: Int64
    fileprivate let modifiedNanoseconds: Int64
}

enum NativeProviderStateRecoveryError: Error, Equatable, LocalizedError {
    case applicationSupportUnsafe
    case noInvalidState
    case stateChanged
    case unsupportedStoredType
    case oversizedConfirmationRequired
    case quarantineUnavailable
    case quarantineCapacityReached
    case resetVerificationFailed

    var errorDescription: String? {
        switch self {
        case .applicationSupportUnsafe:
            return "The private \(ProductBrand.displayName) support directory could not be verified. Nothing was reset."
        case .noInvalidState:
            return "The native provider state is already valid. Nothing was reset."
        case .stateChanged:
            return "The native provider state changed while recovery was open. Review it again before resetting."
        case .unsupportedStoredType:
            return "The damaged preference could not be copied into a recovery file. Nothing was reset."
        case .oversizedConfirmationRequired:
            return "The damaged preference is too large for the bounded recovery folder. A separate confirmation is required to reset it without an exact copy."
        case .quarantineUnavailable:
            return "An exact private recovery copy could not be created. Nothing was reset."
        case .quarantineCapacityReached:
            return "The private provider-recovery folder is full. Nothing was reset. Review its retained copies before trying again."
        case .resetVerificationFailed:
            return "The safe replacement state could not be verified. The recovery copies were retained."
        }
    }
}

/// Inspects the two non-secret native documents that jointly authorize a
/// provider route. Invalid bytes are never replaced implicitly. An explicit
/// reset first writes the exact current bytes to private, fsynced 0600 files,
/// then installs either the safe local selection or a zero-origin consent
/// state and verifies both through their ordinary stores.
final class NativeProviderStateRecovery: @unchecked Sendable {
    static let maximumDocumentBytes = 1 * 1_024 * 1_024
    static let maximumQuarantineBytes = 64 * 1_024 * 1_024
    static let maximumQuarantineFiles = 32
    static let maximumQuarantineAggregateBytes = 256 * 1_024 * 1_024
    static let directoryName = "ProviderStateRecovery"

    private let defaults: UserDefaults
    private let applicationSupport: URL
    private let uuid: @Sendable () -> UUID
    private let fileManager: FileManager

    init(
        defaults: UserDefaults = .standard,
        applicationSupport: URL,
        fileManager: FileManager = .default,
        uuid: @escaping @Sendable () -> UUID = { UUID() }
    ) {
        self.defaults = defaults
        self.applicationSupport = applicationSupport.standardizedFileURL
        self.fileManager = fileManager
        self.uuid = uuid
    }

    func inspect() -> NativeProviderStateInspection {
        let issues = NativeProviderStateDocument.allCases.compactMap(issue(for:))
        guard issues.isEmpty else {
            return NativeProviderStateInspection(issues: issues, routeIssue: nil)
        }
        let settings = (try? ModelProviderSettingsStore(defaults: defaults).load()) ?? nil
        let selection = settings?.defaultSelection ?? .defaultLocal
        guard Self.safeSelection(selection) else {
            return NativeProviderStateInspection(issues: [], routeIssue: .invalidSelection)
        }
        if selection.route.provider != BuiltInProviderDescriptors.ollama.id {
            guard let consent = try? ProviderConsentStore(defaults: defaults).load(),
                  ProviderEgressPolicy.allowedOrigins(selection: selection, consent: consent).count == 1 else {
                return NativeProviderStateInspection(issues: [], routeIssue: .consentUnavailable)
            }
        }
        return NativeProviderStateInspection(issues: [], routeIssue: nil)
    }

    /// This method is intentionally named for its UI contract: production may
    /// call it only after a modal, explicit user confirmation. Healthy state is
    /// never accepted as a reset target.
    func resetAfterExplicitConfirmation(
        expected inspection: NativeProviderStateInspection,
        validateBeforeCommit: (() throws -> Void)? = nil
    ) throws -> NativeProviderStateRecoveryReceipt {
        try reset(
            expected: inspection,
            allowUnquarantinedOversized: false,
            validateBeforeCommit: validateBeforeCommit
        )
    }

    /// A distinct UI confirmation is required when hostile or accidental state
    /// exceeds the bounded quarantine contract. Exact type/length/SHA remains
    /// rechecked, but the oversized bytes are not copied or loaded a second
    /// time merely to make reset possible.
    func resetOversizedAfterExplicitDoubleConfirmation(
        expected inspection: NativeProviderStateInspection,
        validateBeforeCommit: (() throws -> Void)? = nil
    ) throws -> NativeProviderStateRecoveryReceipt {
        guard inspection.issues.contains(where: Self.requiresResetWithoutRecoveryCopy) else {
            throw NativeProviderStateRecoveryError.noInvalidState
        }
        return try reset(
            expected: inspection,
            allowUnquarantinedOversized: true,
            validateBeforeCommit: validateBeforeCommit
        )
    }

    /// Invalid property-list types can be larger than the quarantine limit too;
    /// the second-confirmation boundary is based on the exact encoded byte
    /// count, not merely the decoder's failure classification.
    static func requiresResetWithoutRecoveryCopy(_ issue: NativeProviderStateIssue) -> Bool {
        issue.fingerprint.byteCount > maximumQuarantineBytes
    }

    private func reset(
        expected inspection: NativeProviderStateInspection,
        allowUnquarantinedOversized: Bool,
        validateBeforeCommit: (() throws -> Void)?
    ) throws -> NativeProviderStateRecoveryReceipt {
        guard inspection.permitsStateReset else { throw NativeProviderStateRecoveryError.noInvalidState }
        let current = inspect()
        guard current == inspection else { throw NativeProviderStateRecoveryError.stateChanged }
        let directory = try prepareRecoveryDirectory()

        var payloads: [NativeProviderStateDocument: Data] = [:]
        var originals: [NativeProviderStateDocument: Any] = [:]
        var resetWithoutCopy = Set<NativeProviderStateDocument>()
        for document in inspection.affectedDocuments {
            guard let stored = defaults.object(forKey: document.defaultsKey) else {
                throw NativeProviderStateRecoveryError.unsupportedStoredType
            }
            originals[document] = stored
            guard let issue = inspection.issues.first(where: { $0.document == document }) else {
                throw NativeProviderStateRecoveryError.stateChanged
            }
            if Self.requiresResetWithoutRecoveryCopy(issue) {
                guard allowUnquarantinedOversized else {
                    throw NativeProviderStateRecoveryError.oversizedConfirmationRequired
                }
                resetWithoutCopy.insert(document)
                continue
            }
            guard let data = Self.preservedBytes(from: stored),
                  data.count <= Self.maximumQuarantineBytes else {
                throw NativeProviderStateRecoveryError.unsupportedStoredType
            }
            payloads[document] = data
        }

        var quarantined: [NativeProviderStateDocument: URL] = [:]
        do {
            try Self.requireQuarantineCapacity(
                directory: directory,
                addingFiles: payloads.count,
                addingBytes: payloads.values.reduce(0) { $0 + $1.count },
                fileManager: fileManager
            )
            // A document larger than the bounded quarantine contract is
            // deliberately absent from `payloads` after the user's separate
            // no-copy confirmation. Only write the documents for which an
            // exact recovery payload was admitted.
            for document in payloads.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
                guard let data = payloads[document] else {
                    throw NativeProviderStateRecoveryError.quarantineUnavailable
                }
                let destination = directory.appendingPathComponent(
                    "\(document.fileStem)-\(uuid().uuidString.lowercased()).recovery",
                    isDirectory: false
                )
                try Self.writeExclusivePrivate(data, to: destination)
                quarantined[document] = destination
            }
            try Self.syncDirectory(directory)
        } catch let error as NativeProviderStateRecoveryError {
            throw error
        } catch {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }

        // The global lifecycle permit is revalidated at the last possible
        // point: recovery copies are durable, but no provider namespace has
        // yet changed.
        try validateBeforeCommit?()
        if inspection.affectedDocuments.contains(.modelSettings) {
            let encoded = try JSONEncoder().encode(ModelProviderSettings(defaultSelection: .defaultLocal))
            defaults.set(encoded, forKey: ModelProviderSettingsStore.settingsKey)
        }
        if inspection.affectedDocuments.contains(.providerConsent) {
            let encoded = try JSONEncoder().encode(ProviderConsentState())
            defaults.set(encoded, forKey: ProviderConsentStore.stateKey)
        }

        do {
            if inspection.affectedDocuments.contains(.modelSettings) {
                guard try ModelProviderSettingsStore(defaults: defaults).load()?.defaultSelection == .defaultLocal else {
                    throw NativeProviderStateRecoveryError.resetVerificationFailed
                }
            }
            if inspection.affectedDocuments.contains(.providerConsent) {
                let consent = try ProviderConsentStore(defaults: defaults).load()
                guard consent.activeProvider == nil, consent.grants.isEmpty else {
                    throw NativeProviderStateRecoveryError.resetVerificationFailed
                }
            }
        } catch let error as NativeProviderStateRecoveryError {
            for (document, stored) in originals { defaults.set(stored, forKey: document.defaultsKey) }
            throw error
        } catch {
            for (document, stored) in originals { defaults.set(stored, forKey: document.defaultsKey) }
            throw NativeProviderStateRecoveryError.resetVerificationFailed
        }
        return NativeProviderStateRecoveryReceipt(
            recoveryDirectory: directory,
            quarantinedFiles: quarantined,
            resetWithoutRecoveryCopy: resetWithoutCopy
        )
    }

    /// Returns only attested, owner-only regular recovery copies. Any unknown
    /// node or unsafe metadata fails closed instead of being hidden from the
    /// inventory or touched by a delete operation.
    func recoveryArchives() throws -> [NativeProviderStateRecoveryArchive] {
        guard Self.secureDirectory(applicationSupport) else {
            throw NativeProviderStateRecoveryError.applicationSupportUnsafe
        }
        let directory = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        guard Self.nodeExists(directory) else { return [] }
        guard Self.secureDirectory(directory) else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        return try Self.attestedArchives(in: directory, fileManager: fileManager)
            .sorted {
                if $0.modifiedAt != $1.modifiedAt { return $0.modifiedAt < $1.modifiedAt }
                return $0.url.lastPathComponent < $1.url.lastPathComponent
            }
    }

    /// The caller must present an explicit confirmation naming this copy.
    /// Canonical parent and a fresh inode attestation are required immediately
    /// before unlinking, so a UI-stale or replaced path cannot be deleted.
    func deleteRecoveryArchiveAfterExplicitConfirmation(_ expected: NativeProviderStateRecoveryArchive) throws {
        let archives = try recoveryArchives()
        guard archives.contains(expected) else { throw NativeProviderStateRecoveryError.stateChanged }
        let directory = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        let directoryDescriptor = try Self.openAttestedRecoveryDirectory(directory)
        defer { _ = Darwin.close(directoryDescriptor) }
        try Self.unlinkAttestedArchive(
            expected,
            directory: directory,
            directoryDescriptor: directoryDescriptor
        )
        try Self.syncDirectory(descriptor: directoryDescriptor)
    }

    /// The caller must separately confirm clearing every retained copy. The
    /// fresh inventory makes hostile prepopulation a fail-closed no-op.
    func clearRecoveryArchivesAfterExplicitConfirmation(
        expected: [NativeProviderStateRecoveryArchive]
    ) throws {
        let current = try recoveryArchives()
        guard current == expected else { throw NativeProviderStateRecoveryError.stateChanged }
        let directory = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        let directoryDescriptor = try Self.openAttestedRecoveryDirectory(directory)
        defer { _ = Darwin.close(directoryDescriptor) }
        for archive in current {
            try Self.unlinkAttestedArchive(
                archive,
                directory: directory,
                directoryDescriptor: directoryDescriptor
            )
        }
        try Self.syncDirectory(descriptor: directoryDescriptor)
    }

    private func issue(for document: NativeProviderStateDocument) -> NativeProviderStateIssue? {
        guard let stored = defaults.object(forKey: document.defaultsKey) else { return nil }
        guard let preserved = Self.preservedValue(from: stored) else {
            return NativeProviderStateIssue(
                document: document,
                kind: .invalidStoredType,
                fingerprint: .init(encoding: .binaryPropertyList, byteCount: 0, sha256: "unavailable")
            )
        }
        let fingerprint = NativeProviderStateFingerprint(
            encoding: preserved.encoding,
            byteCount: preserved.data.count,
            sha256: SHA256.hash(data: preserved.data).map { String(format: "%02x", $0) }.joined()
        )
        guard let data = stored as? Data else {
            return NativeProviderStateIssue(document: document, kind: .invalidStoredType, fingerprint: fingerprint)
        }
        guard !data.isEmpty, data.count <= Self.maximumDocumentBytes else {
            return NativeProviderStateIssue(
                document: document,
                kind: data.isEmpty ? .corrupt : .oversized,
                fingerprint: fingerprint
            )
        }
        do {
            switch document {
            case .modelSettings:
                let settings = try JSONDecoder().decode(ModelProviderSettings.self, from: data)
                guard Self.safeSelection(settings.defaultSelection) else {
                    return NativeProviderStateIssue(
                        document: document,
                        kind: .invalidContents,
                        fingerprint: fingerprint
                    )
                }
            case .providerConsent:
                let consent = try JSONDecoder().decode(ProviderConsentState.self, from: data)
                guard Self.safeConsent(consent) else {
                    return NativeProviderStateIssue(
                        document: document,
                        kind: .invalidContents,
                        fingerprint: fingerprint
                    )
                }
            }
            return nil
        } catch {
            if let future = Self.futureSchema(in: data, document: document) {
                return NativeProviderStateIssue(document: document, kind: future, fingerprint: fingerprint)
            }
            // The typed decoders also enforce semantic bounds (for example,
            // provider/model identifier lengths). A supported, syntactically
            // valid JSON document that fails one of those checks is invalid
            // state, not corrupt bytes. Preserve that distinction even when a
            // bound is enforced during decoding rather than by `safeSelection`.
            if (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil {
                return NativeProviderStateIssue(
                    document: document,
                    kind: .invalidContents,
                    fingerprint: fingerprint
                )
            }
            return NativeProviderStateIssue(document: document, kind: .corrupt, fingerprint: fingerprint)
        }
    }

    private static func futureSchema(
        in data: Data,
        document: NativeProviderStateDocument
    ) -> NativeProviderStateFailureKind? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        switch document {
        case .modelSettings:
            let root = object["schemaVersion"] as? Int
            let selection = (object["defaultSelection"] as? [String: Any])?["schemaVersion"] as? Int
            if let found = [root, selection].compactMap({ $0 }).max(),
               found > ModelProviderSettings.currentSchemaVersion {
                return .futureSchema(found: found, supported: ModelProviderSettings.currentSchemaVersion)
            }
        case .providerConsent:
            if let found = object["schemaVersion"] as? Int,
               found > ProviderConsentState.currentSchemaVersion {
                return .futureSchema(found: found, supported: ProviderConsentState.currentSchemaVersion)
            }
        }
        return nil
    }

    private static func safeSelection(_ selection: ModelSelection) -> Bool {
        func safe(_ value: String, maximumBytes: Int) -> Bool {
            !value.isEmpty
                && value.utf8.count <= maximumBytes
                && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        }
        return safe(selection.route.provider.rawValue, maximumBytes: 256)
            && safe(selection.route.model.rawValue, maximumBytes: 512)
            && selection.reasoningEffort.map { safe($0, maximumBytes: 128) } ?? true
    }

    private static func safeConsent(_ consent: ProviderConsentState) -> Bool {
        func safeIdentifier(_ value: String) -> Bool {
            !value.isEmpty
                && value.utf8.count <= 256
                && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        }
        guard consent.grants.count <= 128,
              consent.activeProvider.map({ safeIdentifier($0.rawValue) }) ?? true else {
            return false
        }
        var seenProviders = Set<ProviderID>()
        return consent.grants.allSatisfy { grant in
            guard safeIdentifier(grant.provider.rawValue),
                  seenProviders.insert(grant.provider).inserted else { return false }
            if let reference = grant.credentialReference?.rawValue {
                guard reference.utf8.count <= 256,
                      reference.first?.isLetter == true,
                      reference.unicodeScalars.allSatisfy({ scalar in
                          scalar.isASCII
                              && ((65...90).contains(scalar.value)
                                  || (48...57).contains(scalar.value)
                                  || scalar.value == 95)
                      }) else { return false }
            }
            guard let origin = grant.origin else { return grant.boundary == .onDevice }
            var components = URLComponents()
            components.scheme = origin.scheme
            components.host = origin.host
            components.port = origin.port
            guard let url = components.url,
                  let normalized = ProviderNetworkOrigin(url: url) else { return false }
            switch grant.boundary {
            case .onDevice:
                return ProviderNetworkOrigin.isLocalAddress(normalized.host)
            case .localNetwork:
                return ProviderNetworkOrigin.isLocalAddress(normalized.host)
            case .cloud:
                return normalized.scheme == "https"
                    && !ProviderNetworkOrigin.isLocalAddress(normalized.host)
            }
        }
    }

    private static func preservedBytes(from stored: Any) -> Data? {
        preservedValue(from: stored)?.data
    }

    private static func preservedValue(
        from stored: Any
    ) -> (data: Data, encoding: NativeProviderStateFingerprint.Encoding)? {
        if let data = stored as? Data { return (data, .data) }
        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: stored,
            format: .binary,
            options: 0
        ) else { return nil }
        return (data, .binaryPropertyList)
    }

    private func prepareRecoveryDirectory() throws -> URL {
        guard Self.secureDirectory(applicationSupport) else {
            throw NativeProviderStateRecoveryError.applicationSupportUnsafe
        }
        let directory = applicationSupport.appendingPathComponent(Self.directoryName, isDirectory: true)
        if !Self.nodeExists(directory) {
            do {
                try fileManager.createDirectory(at: directory, withIntermediateDirectories: false)
                try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            } catch {
                throw NativeProviderStateRecoveryError.quarantineUnavailable
            }
        }
        guard Self.secureDirectory(directory) else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        return directory
    }

    private static func writeExclusivePrivate(_ data: Data, to url: URL) throws {
        let descriptor = Darwin.open(
            url.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw NativeProviderStateRecoveryError.quarantineUnavailable }
        var offset = 0
        let wrote = data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return data.isEmpty }
            while offset < data.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        var metadata = stat()
        let safe = Darwin.fstat(descriptor, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_mode & 0o777 == 0o600
            && metadata.st_size == off_t(data.count)
        let synced = wrote && safe && Darwin.fsync(descriptor) == 0
        let closed = Darwin.close(descriptor) == 0
        guard synced, closed else {
            _ = Darwin.unlink(url.path)
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
    }

    private static func syncDirectory(_ url: URL) throws {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw NativeProviderStateRecoveryError.quarantineUnavailable }
        let synced = (try? syncDirectory(descriptor: descriptor)) != nil
        let closed = Darwin.close(descriptor) == 0
        guard synced, closed else { throw NativeProviderStateRecoveryError.quarantineUnavailable }
    }

    private static func syncDirectory(descriptor: Int32) throws {
        guard Darwin.fsync(descriptor) == 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
    }

    private static func requireQuarantineCapacity(
        directory: URL,
        addingFiles: Int,
        addingBytes: Int,
        fileManager: FileManager
    ) throws {
        let archives = try attestedArchives(in: directory, fileManager: fileManager)
        let aggregate = archives.reduce(0) { $0 + $1.byteCount }
        guard archives.count + addingFiles <= maximumQuarantineFiles,
              addingBytes >= 0,
              aggregate <= maximumQuarantineAggregateBytes - addingBytes else {
            throw NativeProviderStateRecoveryError.quarantineCapacityReached
        }
    }

    private static func attestedArchives(
        in directory: URL,
        fileManager: FileManager
    ) throws -> [NativeProviderStateRecoveryArchive] {
        _ = fileManager
        let directoryDescriptor = try openAttestedRecoveryDirectory(directory)
        defer { _ = Darwin.close(directoryDescriptor) }
        let names = try archiveNames(directoryDescriptor: directoryDescriptor)
        var aggregate = 0
        var archives: [NativeProviderStateRecoveryArchive] = []
        for name in names {
            let opened = try openAttestedArchive(
                named: name,
                directory: directory,
                directoryDescriptor: directoryDescriptor
            )
            _ = Darwin.close(opened.descriptor)
            aggregate += opened.archive.byteCount
            guard archives.count < maximumQuarantineFiles,
                  aggregate <= maximumQuarantineAggregateBytes else {
                throw NativeProviderStateRecoveryError.quarantineCapacityReached
            }
            archives.append(opened.archive)
        }
        return archives
    }

    private struct OpenedRecoveryArchive {
        let descriptor: Int32
        let archive: NativeProviderStateRecoveryArchive
    }

    private static func openAttestedRecoveryDirectory(_ directory: URL) throws -> Int32 {
        guard secureDirectory(directory) else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        var pathMetadata = stat()
        guard Darwin.lstat(directory.path, &pathMetadata) == 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        var openedMetadata = stat()
        guard Darwin.fstat(descriptor, &openedMetadata) == 0,
              openedMetadata.st_mode & S_IFMT == S_IFDIR,
              openedMetadata.st_uid == geteuid(),
              openedMetadata.st_mode & 0o777 == 0o700,
              openedMetadata.st_dev == pathMetadata.st_dev,
              openedMetadata.st_ino == pathMetadata.st_ino else {
            _ = Darwin.close(descriptor)
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        return descriptor
    }

    private static func archiveNames(directoryDescriptor: Int32) throws -> [String] {
        let enumerationDescriptor = Darwin.dup(directoryDescriptor)
        guard enumerationDescriptor >= 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        guard let stream = Darwin.fdopendir(enumerationDescriptor) else {
            _ = Darwin.close(enumerationDescriptor)
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        defer { Darwin.closedir(stream) }

        var names: [String] = []
        while true {
            errno = 0
            guard let entry = Darwin.readdir(stream) else {
                guard errno == 0 else {
                    throw NativeProviderStateRecoveryError.quarantineUnavailable
                }
                return names
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw NativeProviderStateRecoveryError.quarantineUnavailable
            }
            if name == "." || name == ".." { continue }
            guard names.count < maximumQuarantineFiles + 1 else {
                throw NativeProviderStateRecoveryError.quarantineUnavailable
            }
            names.append(name)
        }
    }

    private static func openAttestedArchive(
        named name: String,
        directory: URL,
        directoryDescriptor: Int32
    ) throws -> OpenedRecoveryArchive {
        let entry = directory.appendingPathComponent(name, isDirectory: false)
        guard entry.pathExtension == "recovery",
              entry.lastPathComponent == name,
              entry.deletingLastPathComponent().standardizedFileURL == directory else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
        let descriptor = Darwin.openat(
            directoryDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }

        do {
            var before = stat()
            guard Darwin.fstat(descriptor, &before) == 0,
                  before.st_mode & S_IFMT == S_IFREG,
                  before.st_uid == geteuid(),
                  before.st_nlink == 1,
                  before.st_mode & 0o777 == 0o600,
                  before.st_size >= 0,
                  before.st_size <= off_t(maximumQuarantineBytes),
                  let byteCount = Int(exactly: before.st_size) else {
                throw NativeProviderStateRecoveryError.quarantineUnavailable
            }

            var hasher = SHA256()
            var total = 0
            var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
            while true {
                let count = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(descriptor, bytes.baseAddress, bytes.count)
                }
                if count < 0 {
                    if errno == EINTR { continue }
                    throw NativeProviderStateRecoveryError.quarantineUnavailable
                }
                if count == 0 { break }
                total += count
                guard total <= byteCount else {
                    throw NativeProviderStateRecoveryError.quarantineUnavailable
                }
                hasher.update(data: Data(buffer.prefix(count)))
            }

            var after = stat()
            guard Darwin.fstat(descriptor, &after) == 0,
                  before.st_dev == after.st_dev,
                  before.st_ino == after.st_ino,
                  before.st_mode == after.st_mode,
                  before.st_uid == after.st_uid,
                  before.st_nlink == after.st_nlink,
                  before.st_size == after.st_size,
                  before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
                  before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                  total == byteCount else {
                throw NativeProviderStateRecoveryError.quarantineUnavailable
            }

            let modifiedSeconds = Int64(before.st_mtimespec.tv_sec)
            let modifiedNanoseconds = Int64(before.st_mtimespec.tv_nsec)
            return OpenedRecoveryArchive(
                descriptor: descriptor,
                archive: NativeProviderStateRecoveryArchive(
                    url: entry,
                    byteCount: byteCount,
                    modifiedAt: Date(
                        timeIntervalSince1970: TimeInterval(modifiedSeconds)
                            + TimeInterval(modifiedNanoseconds) / 1_000_000_000
                    ),
                    device: UInt64(bitPattern: Int64(before.st_dev)),
                    inode: UInt64(before.st_ino),
                    contentSHA256: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
                    modifiedSeconds: modifiedSeconds,
                    modifiedNanoseconds: modifiedNanoseconds
                )
            )
        } catch {
            _ = Darwin.close(descriptor)
            throw error
        }
    }

    private static func unlinkAttestedArchive(
        _ expected: NativeProviderStateRecoveryArchive,
        directory: URL,
        directoryDescriptor: Int32
    ) throws {
        let name = expected.url.lastPathComponent
        guard expected.url.deletingLastPathComponent().standardizedFileURL == directory else {
            throw NativeProviderStateRecoveryError.stateChanged
        }
        let opened = try openAttestedArchive(
            named: name,
            directory: directory,
            directoryDescriptor: directoryDescriptor
        )
        defer { _ = Darwin.close(opened.descriptor) }
        guard opened.archive == expected else {
            throw NativeProviderStateRecoveryError.stateChanged
        }

        var pathMetadata = stat()
        guard Darwin.fstatat(
            directoryDescriptor,
            name,
            &pathMetadata,
            AT_SYMLINK_NOFOLLOW
        ) == 0,
              UInt64(bitPattern: Int64(pathMetadata.st_dev)) == expected.device,
              UInt64(pathMetadata.st_ino) == expected.inode,
              Int64(pathMetadata.st_size) == Int64(expected.byteCount),
              Int64(pathMetadata.st_mtimespec.tv_sec) == expected.modifiedSeconds,
              Int64(pathMetadata.st_mtimespec.tv_nsec) == expected.modifiedNanoseconds else {
            throw NativeProviderStateRecoveryError.stateChanged
        }
        guard Darwin.unlinkat(directoryDescriptor, name, 0) == 0 else {
            throw NativeProviderStateRecoveryError.quarantineUnavailable
        }
    }

    private static func nodeExists(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0
    }

    private static func secureDirectory(_ url: URL) -> Bool {
        var metadata = stat()
        return url.path == url.standardizedFileURL.path
            && url.path == url.resolvingSymlinksInPath().standardizedFileURL.path
            && Darwin.lstat(url.path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_mode & 0o777 == 0o700
    }
}
