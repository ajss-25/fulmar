import CryptoKit
import Darwin
import Foundation

struct PluginTrustFinding: Codable, Equatable, Identifiable {
    enum Status: String, Codable { case builtIn, approved, blocked }

    let id: String
    let name: String
    let declaredVersion: String
    let fingerprint: String
    let source: String
    let status: Status
}

final class PluginTrustStore {
    struct Limits: Sendable {
        var maximumDeclarationFileBytes: Int64
        var maximumDeclarationBytes: Int64
        var maximumDeclarations: Int
        var maximumEntries: Int
        var maximumDepth: Int
        var maximumPathBytes: Int
        var maximumFileBytes: Int64
        var maximumAggregateBytes: Int64
        var scanDuration: TimeInterval

        init(
            maximumDeclarationFileBytes: Int64 = 512 * 1_024,
            maximumDeclarationBytes: Int64 = 1 * 1_024 * 1_024,
            maximumDeclarations: Int = 256,
            maximumEntries: Int = 10_000,
            maximumDepth: Int = 32,
            maximumPathBytes: Int = 4_096,
            maximumFileBytes: Int64 = 16 * 1_024 * 1_024,
            maximumAggregateBytes: Int64 = 128 * 1_024 * 1_024,
            scanDuration: TimeInterval = 2
        ) {
            self.maximumDeclarationFileBytes = maximumDeclarationFileBytes
            self.maximumDeclarationBytes = maximumDeclarationBytes
            self.maximumDeclarations = maximumDeclarations
            self.maximumEntries = maximumEntries
            self.maximumDepth = maximumDepth
            self.maximumPathBytes = maximumPathBytes
            self.maximumFileBytes = maximumFileBytes
            self.maximumAggregateBytes = maximumAggregateBytes
            self.scanDuration = scanDuration
        }

        fileprivate var isValid: Bool {
            maximumDeclarationFileBytes > 0
                && maximumDeclarationBytes >= maximumDeclarationFileBytes
                && maximumDeclarations > 0
                && maximumEntries > 0
                && maximumDepth >= 0
                && maximumDepth <= 128
                && maximumPathBytes > 0
                && maximumPathBytes <= 64 * 1_024
                && maximumFileBytes >= 0
                && maximumAggregateBytes >= maximumFileBytes
                && scanDuration.isFinite
                && scanDuration >= 0
                && scanDuration <= 30
        }
    }

    static let blockedFingerprint = "blocked-untrusted-plugin-content-v1"
    static let oversizeFingerprint = "blocked-oversize-plugin-content-v1"
    static let deadlineFingerprint = "blocked-plugin-audit-deadline-v1"
    private static let maximumStoredApprovals = 256
    private static let maximumApprovalStoreBytes: Int64 = 256 * 1_024

    private static let reviewedBuiltInDeclarations: Set<String> = [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app",
        "@local-harness/dsh-client-security-bridge",
        "@local-harness/dsh-credentials-keychain",
        "@local-harness/dsh-mcp-guarded",
        "@local-harness/dsh-web-fetch-safe",
        "cordis:group"
    ]
    private static let declarationFailureID = "__local_harness_plugin_declarations__"
    private static let allowedPluginName = try! NSRegularExpression(
        pattern: #"^(?:@[a-z0-9._-]+/)?[a-z0-9._-]+$"#,
        options: [.caseInsensitive]
    )

    private struct Approval: Codable {
        let name: String
        let fingerprint: String
        let approvedAt: Date
    }

    private struct ApprovalDirectoryIdentity: Equatable {
        let device: UInt64
        let inode: UInt64
    }

    private enum AuditFailure: Error {
        case blocked
        case oversize
        case deadline

        var fingerprint: String {
            switch self {
            case .blocked: PluginTrustStore.blockedFingerprint
            case .oversize: PluginTrustStore.oversizeFingerprint
            case .deadline: PluginTrustStore.deadlineFingerprint
            }
        }
    }

    /// Distinguishes a failure before publication from a failure after the
    /// atomic rename. Once the new bytes are the directory entry, reverting
    /// only the in-memory approval would create a restart-dependent trust
    /// decision. The caller therefore retains the candidate in memory while
    /// surfacing the durability uncertainty to the UI.
    private enum ApprovalPersistenceFailure: Error {
        case notCommitted
        case committedDurabilityUncertain
    }

    private struct FingerprintResult {
        let value: String
        let approvable: Bool

        static func blocked(_ failure: AuditFailure) -> Self {
            Self(value: failure.fingerprint, approvable: false)
        }
    }

    private struct AuditDeadline {
        let uptimeNanoseconds: UInt64

        init(duration: TimeInterval) {
            let started = DispatchTime.now().uptimeNanoseconds
            let nanoseconds = UInt64(max(0, min(duration, 30)) * 1_000_000_000)
            let (candidate, overflow) = started.addingReportingOverflow(nanoseconds)
            uptimeNanoseconds = overflow ? UInt64.max : candidate
        }

        func check() throws {
            if DispatchTime.now().uptimeNanoseconds >= uptimeNanoseconds {
                throw AuditFailure.deadline
            }
        }
    }

    private struct ScanState {
        var entries = 0
        var regularFiles = 0
        var aggregateBytes: Int64 = 0
    }

    private enum DeclarationRead {
        case missing
        case data(Data)
    }

    private let fileManager = FileManager.default
    private let approvalDirectory: URL
    private let approvalDirectoryIdentity: ApprovalDirectoryIdentity?
    private let storeURL: URL
    private let profileRoot: URL
    private let limits: Limits
    private var approvals: [String: Approval] = [:]

    init(
        applicationSupport: URL,
        profileRoot: URL? = nil,
        limits: Limits = Limits()
    ) {
        let directory = applicationSupport.appendingPathComponent("Security", isDirectory: true)
        approvalDirectory = directory
        approvalDirectoryIdentity = Self.prepareApprovalDirectory(
            applicationSupport: applicationSupport,
            directory: directory
        )
        storeURL = directory.appendingPathComponent("plugin-trust.json")
        self.profileRoot = profileRoot ?? fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".dsh/profiles", isDirectory: true)
        self.limits = limits
        approvals = approvalDirectoryIdentity.map {
            Self.loadApprovals(
                from: directory,
                filename: storeURL.lastPathComponent,
                expectedDirectory: $0
            )
        } ?? [:]
    }

    func audit(profile: String = "web") -> [PluginTrustFinding] {
        guard approvalDirectoryIdentity != nil else {
            return [declarationFailure(source: "approval storage", failure: .blocked)]
        }
        guard limits.isValid else {
            return [declarationFailure(source: "limits", failure: .blocked)]
        }
        let deadline = AuditDeadline(duration: limits.scanDuration)
        guard Self.isSafeProfileName(profile) else {
            return [declarationFailure(source: "profile", failure: .blocked)]
        }
        let profileDirectory = profileRoot.appendingPathComponent(profile, isDirectory: true)

        let profileDescriptor: Int32
        do {
            guard let opened = try openProfileDirectory(profileDirectory, deadline: deadline) else { return [] }
            profileDescriptor = opened
        } catch let failure as AuditFailure {
            return [declarationFailure(source: "profile", failure: failure)]
        } catch {
            return [declarationFailure(source: "profile", failure: .blocked)]
        }
        defer { Darwin.close(profileDescriptor) }

        var declarations: [(name: String, version: String, source: String)] = []
        var declarationBytes: Int64 = 0
        do {
            switch try readDeclaration(
                named: "package.json",
                from: profileDescriptor,
                totalBytes: &declarationBytes,
                deadline: deadline
            ) {
            case .missing:
                break
            case .data(let data):
                guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw AuditFailure.blocked
                }
                if let rawDependencies = object["dependencies"] {
                    guard let dependencies = rawDependencies as? [String: String] else {
                        throw AuditFailure.blocked
                    }
                    for (name, version) in dependencies.sorted(by: { $0.key < $1.key }) {
                        try appendDeclaration(
                            name: name,
                            version: version,
                            source: "package.json",
                            to: &declarations,
                            deadline: deadline
                        )
                    }
                }
                if let rawDSH = object["dsh"] {
                    guard let dsh = rawDSH as? [String: Any] else { throw AuditFailure.blocked }
                    if let rawProfile = dsh["profile"] {
                        guard let profileObject = rawProfile as? [String: Any] else { throw AuditFailure.blocked }
                        if let rawBundles = profileObject["bundles"] {
                            guard let bundles = rawBundles as? [String] else { throw AuditFailure.blocked }
                            for name in bundles {
                                try appendDeclaration(
                                    name: name,
                                    version: "bundle",
                                    source: "package.json bundle",
                                    to: &declarations,
                                    deadline: deadline
                                )
                            }
                        }
                    }
                }
                try deadline.check()
            }

            for filename in ["cordis.yml", "cordis.patch.yml"] {
                switch try readDeclaration(
                    named: filename,
                    from: profileDescriptor,
                    totalBytes: &declarationBytes,
                    deadline: deadline
                ) {
                case .missing:
                    continue
                case .data(let data):
                    guard let text = String(data: data, encoding: .utf8) else {
                        throw AuditFailure.blocked
                    }
                    for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
                        try deadline.check()
                        let line = rawLine.trimmingCharacters(in: .whitespaces)
                        guard line.hasPrefix("name:") else { continue }
                        let name = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                            .trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
                        if !name.isEmpty, !name.hasPrefix("!!js") {
                            try appendDeclaration(
                                name: name,
                                version: "profile",
                                source: filename,
                                to: &declarations,
                                deadline: deadline
                            )
                        }
                    }
                }
            }
        } catch let failure as AuditFailure {
            return [declarationFailure(source: "profile declarations", failure: failure)]
        } catch {
            return [declarationFailure(source: "profile declarations", failure: .blocked)]
        }

        var seen = Set<String>()
        var findings: [PluginTrustFinding] = []
        for declaration in declarations.sorted(by: {
            $0.name == $1.name ? $0.source < $1.source : $0.name < $1.name
        }) {
            guard seen.insert(declaration.name).inserted else { continue }
            do {
                try deadline.check()
                let reviewedBuiltIn = Self.reviewedBuiltInDeclarations.contains(declaration.name)
                let hasInstalledOverride: Bool
                if Self.isValidPluginName(declaration.name),
                   let overrideDescriptor = try openPackageDirectory(
                       name: declaration.name,
                       profileDescriptor: profileDescriptor,
                       deadline: deadline
                   ) {
                    Darwin.close(overrideDescriptor)
                    hasInstalledOverride = true
                } else {
                    hasInstalledOverride = false
                }
                if reviewedBuiltIn, !hasInstalledOverride {
                    findings.append(PluginTrustFinding(
                        id: declaration.name,
                        name: declaration.name,
                        declaredVersion: declaration.version,
                        fingerprint: Self.declarationFingerprint(
                            name: declaration.name,
                            version: declaration.version
                        ),
                        source: declaration.source,
                        status: .builtIn
                    ))
                    continue
                }

                let result = contentFingerprint(
                    name: declaration.name,
                    version: declaration.version,
                    profileDescriptor: profileDescriptor,
                    deadline: deadline
                )
                let status: PluginTrustFinding.Status = result.approvable
                    && approvals[declaration.name]?.fingerprint == result.value ? .approved : .blocked
                findings.append(PluginTrustFinding(
                    id: declaration.name,
                    name: declaration.name,
                    declaredVersion: declaration.version,
                    fingerprint: result.value,
                    source: declaration.source,
                    status: status
                ))
                if result.value == Self.deadlineFingerprint { break }
            } catch let failure as AuditFailure {
                findings.append(declarationFailure(source: declaration.source, failure: failure))
                break
            } catch {
                findings.append(declarationFailure(source: declaration.source, failure: .blocked))
                break
            }
        }
        return findings.sorted { $0.name < $1.name }
    }

    func approve(_ finding: PluginTrustFinding) throws {
        guard finding.status == .blocked,
              finding.id == finding.name,
              Self.isValidPluginName(finding.name),
              finding.fingerprint.utf8.count == 64,
              finding.fingerprint.utf8.allSatisfy({
                  (48...57).contains($0) || (97...102).contains($0)
              }),
              approvals[finding.name] != nil || approvals.count < Self.maximumStoredApprovals else { return }
        let previous = approvals
        approvals[finding.name] = Approval(
            name: finding.name,
            fingerprint: finding.fingerprint,
            approvedAt: Date()
        )
        do {
            try persist()
        } catch ApprovalPersistenceFailure.committedDurabilityUncertain {
            throw ApprovalPersistenceFailure.committedDurabilityUncertain
        } catch {
            approvals = previous
            throw error
        }
    }

    func revoke(name: String) throws {
        let previous = approvals
        approvals.removeValue(forKey: name)
        do {
            try persist()
        } catch ApprovalPersistenceFailure.committedDurabilityUncertain {
            throw ApprovalPersistenceFailure.committedDurabilityUncertain
        } catch {
            approvals = previous
            throw error
        }
    }

    private func persist() throws {
        guard let approvalDirectoryIdentity else {
            throw ApprovalPersistenceFailure.notCommitted
        }
        guard approvals.count <= Self.maximumStoredApprovals else { throw AuditFailure.oversize }
        let data = try JSONEncoder().encode(approvals)
        guard data.count <= Self.maximumApprovalStoreBytes else { throw AuditFailure.oversize }
        try Self.atomicPrivateApprovalWrite(
            data,
            directory: approvalDirectory,
            filename: storeURL.lastPathComponent,
            expectedDirectory: approvalDirectoryIdentity
        )
    }

    private static func loadApprovals(
        from directory: URL,
        filename: String,
        expectedDirectory: ApprovalDirectoryIdentity
    ) -> [String: Approval] {
        guard let directoryDescriptor = openApprovalDirectory(
            directory,
            expected: expectedDirectory
        ) else { return [:] }
        defer { Darwin.close(directoryDescriptor) }
        let descriptor = filename.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0 else { return [:] }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_uid == geteuid(),
              opened.st_nlink == 1,
              opened.st_size >= 0,
              Int64(opened.st_size) <= maximumApprovalStoreBytes,
              opened.st_mode & mode_t(0o7777) == mode_t(0o600),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            return [:]
        }

        var data = Data()
        data.reserveCapacity(Int(opened.st_size))
        var buffer = [UInt8](repeating: 0, count: 32 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                return [:]
            }
            guard Int64(data.count + count) <= maximumApprovalStoreBytes else { return [:] }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              sameIdentity(opened, after),
              data.count == Int(opened.st_size),
              let decoded = try? JSONDecoder().decode([String: Approval].self, from: data),
              decoded.count <= maximumStoredApprovals else {
            return [:]
        }
        let valid = decoded.allSatisfy { key, approval in
            key == approval.name
                && isValidPluginName(key)
                && key.utf8.count <= 256
                && isValidFingerprint(approval.fingerprint)
                && approval.approvedAt.timeIntervalSinceReferenceDate.isFinite
        }
        return valid ? decoded : [:]
    }

    private static func prepareApprovalDirectory(
        applicationSupport: URL,
        directory: URL
    ) -> ApprovalDirectoryIdentity? {
        guard applicationSupport.isFileURL,
              directory.isFileURL,
              applicationSupport.standardizedFileURL == applicationSupport,
              directory.standardizedFileURL == directory,
              directory.deletingLastPathComponent() == applicationSupport,
              !applicationSupport.path.contains("\0"),
              !directory.path.contains("\0") else { return nil }
        do {
            try FileManager.default.createDirectory(
                at: applicationSupport,
                withIntermediateDirectories: true
            )
        } catch { return nil }

        var supportMetadata = stat()
        guard Darwin.lstat(applicationSupport.path, &supportMetadata) == 0,
              supportMetadata.st_mode & S_IFMT == S_IFDIR,
              supportMetadata.st_uid == geteuid(),
              supportMetadata.st_mode & mode_t(0o022) == 0 else { return nil }

        if Darwin.mkdir(directory.path, mode_t(0o700)) != 0, errno != EEXIST {
            return nil
        }
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }
        guard Darwin.fchmod(descriptor, mode_t(0o700)) == 0 else { return nil }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & mode_t(0o7777) == mode_t(0o700),
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            return nil
        }
        return ApprovalDirectoryIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino)
        )
    }

    private static func openApprovalDirectory(
        _ directory: URL,
        expected: ApprovalDirectoryIdentity
    ) -> Int32? {
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & mode_t(0o7777) == mode_t(0o700),
              UInt64(truncatingIfNeeded: metadata.st_dev) == expected.device,
              UInt64(truncatingIfNeeded: metadata.st_ino) == expected.inode,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            Darwin.close(descriptor)
            return nil
        }
        return descriptor
    }

    private static func atomicPrivateApprovalWrite(
        _ data: Data,
        directory: URL,
        filename: String,
        expectedDirectory: ApprovalDirectoryIdentity
    ) throws {
        guard let directoryDescriptor = openApprovalDirectory(
            directory,
            expected: expectedDirectory
        ) else { throw ApprovalPersistenceFailure.notCommitted }
        defer { Darwin.close(directoryDescriptor) }
        try requireSafeApprovalDestination(
            directoryDescriptor: directoryDescriptor,
            filename: filename
        )

        let temporaryName = ".plugin-trust.\(UUID().uuidString).tmp"
        let descriptor = temporaryName.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else { throw ApprovalPersistenceFailure.notCommitted }
        var descriptorOpen = true
        var temporaryExists = true
        defer {
            if descriptorOpen { Darwin.close(descriptor) }
            if temporaryExists {
                temporaryName.withCString { _ = Darwin.unlinkat(directoryDescriptor, $0, 0) }
            }
        }
        guard CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              writeAll(data, to: descriptor),
              Darwin.fsync(descriptor) == 0 else {
            throw ApprovalPersistenceFailure.notCommitted
        }
        let closeResult = Darwin.close(descriptor)
        descriptorOpen = false
        guard closeResult == 0 else { throw ApprovalPersistenceFailure.notCommitted }

        try requireSafeApprovalDestination(
            directoryDescriptor: directoryDescriptor,
            filename: filename
        )
        let renameResult = temporaryName.withCString { temporary in
            filename.withCString { destination in
                Darwin.renameat(
                    directoryDescriptor,
                    temporary,
                    directoryDescriptor,
                    destination
                )
            }
        }
        guard renameResult == 0 else { throw ApprovalPersistenceFailure.notCommitted }
        temporaryExists = false

        let persisted = filename.withCString {
            Darwin.openat(
                directoryDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard persisted >= 0 else {
            throw ApprovalPersistenceFailure.committedDurabilityUncertain
        }
        defer { Darwin.close(persisted) }
        var metadata = stat()
        guard Darwin.fstat(persisted, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & mode_t(0o7777) == mode_t(0o600),
              metadata.st_size == data.count,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(persisted),
              approvalBytes(on: persisted, match: data),
              Darwin.fsync(directoryDescriptor) == 0 else {
            throw ApprovalPersistenceFailure.committedDurabilityUncertain
        }
    }

    private static func requireSafeApprovalDestination(
        directoryDescriptor: Int32,
        filename: String
    ) throws {
        var metadata = stat()
        let result = filename.withCString {
            Darwin.fstatat(directoryDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return }
            throw ApprovalPersistenceFailure.notCommitted
        }
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & mode_t(0o7777) == mode_t(0o600) else {
            throw ApprovalPersistenceFailure.notCommitted
        }
    }

    private static func approvalBytes(on descriptor: Int32, match expected: Data) -> Bool {
        guard Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else { return false }
        var captured = Data()
        captured.reserveCapacity(expected.count)
        var buffer = [UInt8](repeating: 0, count: 32 * 1_024)
        while captured.count <= expected.count {
            let remaining = expected.count + 1 - captured.count
            let requested = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, requested)
            }
            if count > 0 {
                captured.append(contentsOf: buffer.prefix(count))
            } else if count == 0 {
                break
            } else if errno == EINTR {
                continue
            } else {
                return false
            }
        }
        return captured == expected
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { storage in
            guard let base = storage.baseAddress else { return data.isEmpty }
            var offset = 0
            while offset < storage.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    storage.count - offset
                )
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }

    private static func isValidFingerprint(_ value: String) -> Bool {
        value.utf8.count == 64
            && value.utf8.allSatisfy {
                (48...57).contains($0) || (97...102).contains($0)
            }
    }

    private static func declarationFingerprint(name: String, version: String) -> String {
        SHA256.hash(data: Data("\(name)\u{0}\(version)".utf8))
            .map { String(format: "%02x", $0) }.joined()
    }

    private func declarationFailure(source: String, failure: AuditFailure) -> PluginTrustFinding {
        PluginTrustFinding(
            id: Self.declarationFailureID,
            name: "Untrusted plugin declarations",
            declaredVersion: "blocked",
            fingerprint: failure.fingerprint,
            source: source,
            status: .blocked
        )
    }

    private func appendDeclaration(
        name: String,
        version: String,
        source: String,
        to declarations: inout [(name: String, version: String, source: String)],
        deadline: AuditDeadline
    ) throws {
        try deadline.check()
        guard declarations.count < limits.maximumDeclarations,
              !name.isEmpty,
              name.utf8.count <= 256,
              !name.contains("\0"),
              version.utf8.count <= 256,
              !version.contains("\0") else {
            throw AuditFailure.oversize
        }
        declarations.append((name, version, source))
    }

    private func readDeclaration(
        named name: String,
        from directoryDescriptor: Int32,
        totalBytes: inout Int64,
        deadline: AuditDeadline
    ) throws -> DeclarationRead {
        try deadline.check()
        var pathMetadata = stat()
        guard fstatat(directoryDescriptor, name, &pathMetadata, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return .missing }
            throw AuditFailure.blocked
        }
        guard pathMetadata.st_mode & S_IFMT == S_IFREG,
              pathMetadata.st_nlink == 1,
              pathMetadata.st_size >= 0 else {
            throw AuditFailure.blocked
        }
        let declaredSize = Int64(pathMetadata.st_size)
        guard declaredSize <= limits.maximumDeclarationFileBytes,
              declaredSize <= limits.maximumDeclarationBytes - totalBytes else {
            throw AuditFailure.oversize
        }
        let descriptor = openat(
            directoryDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw AuditFailure.blocked }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_nlink == 1 else {
            throw AuditFailure.blocked
        }

        var data = Data()
        data.reserveCapacity(Int(declaredSize))
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try deadline.check()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw AuditFailure.blocked
            }
            guard Int64(data.count + count) <= limits.maximumDeclarationFileBytes,
                  Int64(data.count + count) <= limits.maximumDeclarationBytes - totalBytes else {
                throw AuditFailure.oversize
            }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.sameIdentity(opened, after),
              Int64(data.count) == declaredSize else {
            throw AuditFailure.blocked
        }
        totalBytes += Int64(data.count)
        return .data(data)
    }

    private func contentFingerprint(
        name: String,
        version: String,
        profileDescriptor: Int32,
        deadline: AuditDeadline
    ) -> FingerprintResult {
        guard Self.isValidPluginName(name) else { return .blocked(.blocked) }
        do {
            try deadline.check()
            guard let packageDescriptor = try openPackageDirectory(
                name: name,
                profileDescriptor: profileDescriptor,
                deadline: deadline
            ) else { return .blocked(.blocked) }
            defer { Darwin.close(packageDescriptor) }
            var rootMetadata = stat()
            guard Darwin.fstat(packageDescriptor, &rootMetadata) == 0,
                  rootMetadata.st_mode & S_IFMT == S_IFDIR else {
                throw AuditFailure.blocked
            }

            var hasher = SHA256()
            Self.hashLengthPrefixed(Data("local-harness-plugin-v2".utf8), into: &hasher)
            Self.hashLengthPrefixed(Data(name.utf8), into: &hasher)
            Self.hashLengthPrefixed(Data(version.utf8), into: &hasher)
            Self.hashLengthPrefixed(
                Data(String(rootMetadata.st_mode & 0o7777, radix: 8).utf8),
                into: &hasher
            )
            var state = ScanState()
            try scanDirectory(
                descriptor: packageDescriptor,
                relativePrefix: "",
                depth: 0,
                state: &state,
                hasher: &hasher,
                deadline: deadline
            )
            guard state.regularFiles > 0 else { throw AuditFailure.blocked }
            try deadline.check()
            return FingerprintResult(
                value: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
                approvable: true
            )
        } catch let failure as AuditFailure {
            return .blocked(failure)
        } catch {
            return .blocked(.blocked)
        }
    }

    private func openProfileDirectory(
        _ profileDirectory: URL,
        deadline: AuditDeadline
    ) throws -> Int32? {
        try deadline.check()
        var rootMetadata = stat()
        guard Darwin.lstat(profileRoot.path, &rootMetadata) == 0 else {
            if errno == ENOENT { return nil }
            throw AuditFailure.blocked
        }
        guard rootMetadata.st_mode & S_IFMT == S_IFDIR else { throw AuditFailure.blocked }
        var pathMetadata = stat()
        guard Darwin.lstat(profileDirectory.path, &pathMetadata) == 0 else {
            if errno == ENOENT { return nil }
            throw AuditFailure.blocked
        }
        guard pathMetadata.st_mode & S_IFMT == S_IFDIR else { throw AuditFailure.blocked }
        let descriptor = Darwin.open(
            profileDirectory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw AuditFailure.blocked }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(pathMetadata, opened),
              opened.st_mode & S_IFMT == S_IFDIR else {
            Darwin.close(descriptor)
            throw AuditFailure.blocked
        }
        return descriptor
    }

    private func openPackageDirectory(
        name: String,
        profileDescriptor: Int32,
        deadline: AuditDeadline
    ) throws -> Int32? {
        try deadline.check()
        var components = ["node_modules"]
        if name.hasPrefix("@") {
            let pieces = name.split(separator: "/", omittingEmptySubsequences: false)
            guard pieces.count == 2 else { throw AuditFailure.blocked }
            components.append(contentsOf: pieces.map(String.init))
        } else {
            components.append(name)
        }

        var current = Darwin.dup(profileDescriptor)
        guard current >= 0 else { throw AuditFailure.blocked }
        for component in components {
            try deadline.check()
            let next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if next < 0 {
                let capturedErrno = errno
                Darwin.close(current)
                if capturedErrno == ENOENT { return nil }
                throw AuditFailure.blocked
            }
            var metadata = stat()
            guard Darwin.fstat(next, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR else {
                Darwin.close(next)
                Darwin.close(current)
                throw AuditFailure.blocked
            }
            Darwin.close(current)
            current = next
        }
        return current
    }

    private func scanDirectory(
        descriptor: Int32,
        relativePrefix: String,
        depth: Int,
        state: inout ScanState,
        hasher: inout SHA256,
        deadline: AuditDeadline
    ) throws {
        try deadline.check()
        guard depth <= limits.maximumDepth else { throw AuditFailure.oversize }
        let iterationDescriptor = Darwin.dup(descriptor)
        guard iterationDescriptor >= 0 else { throw AuditFailure.blocked }
        guard let stream = fdopendir(iterationDescriptor) else {
            Darwin.close(iterationDescriptor)
            throw AuditFailure.blocked
        }
        defer { closedir(stream) }

        var names: [String] = []
        while true {
            try deadline.check()
            errno = 0
            guard let entry = readdir(stream) else {
                if errno != 0 { throw AuditFailure.blocked }
                break
            }
            guard let name = DarwinDirectoryEntry.name(entry) else { throw AuditFailure.blocked }
            if name == "." || name == ".." { continue }
            guard Self.isSafePathComponent(name) else { throw AuditFailure.blocked }
            state.entries += 1
            guard state.entries <= limits.maximumEntries else { throw AuditFailure.oversize }
            names.append(name)
        }
        names.sort()
        try deadline.check()

        for name in names {
            try deadline.check()
            let relative = relativePrefix.isEmpty ? name : "\(relativePrefix)/\(name)"
            guard relative.utf8.count <= limits.maximumPathBytes else { throw AuditFailure.oversize }
            var pathMetadata = stat()
            guard fstatat(descriptor, name, &pathMetadata, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw AuditFailure.blocked
            }
            switch pathMetadata.st_mode & S_IFMT {
            case S_IFDIR:
                guard depth < limits.maximumDepth else { throw AuditFailure.oversize }
                Self.hashEntry(
                    type: "directory",
                    relative: relative,
                    metadata: pathMetadata,
                    into: &hasher
                )
                let child = openat(
                    descriptor,
                    name,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
                guard child >= 0 else { throw AuditFailure.blocked }
                var opened = stat()
                guard Darwin.fstat(child, &opened) == 0,
                      Self.sameIdentity(pathMetadata, opened),
                      opened.st_mode & S_IFMT == S_IFDIR else {
                    Darwin.close(child)
                    throw AuditFailure.blocked
                }
                do {
                    try scanDirectory(
                        descriptor: child,
                        relativePrefix: relative,
                        depth: depth + 1,
                        state: &state,
                        hasher: &hasher,
                        deadline: deadline
                    )
                    Darwin.close(child)
                } catch {
                    Darwin.close(child)
                    throw error
                }
            case S_IFREG:
                guard pathMetadata.st_nlink == 1,
                      pathMetadata.st_size >= 0 else { throw AuditFailure.blocked }
                let size = Int64(pathMetadata.st_size)
                guard size <= limits.maximumFileBytes,
                      size <= limits.maximumAggregateBytes - state.aggregateBytes else {
                    throw AuditFailure.oversize
                }
                state.aggregateBytes += size
                state.regularFiles += 1
                Self.hashEntry(
                    type: "regular",
                    relative: relative,
                    metadata: pathMetadata,
                    into: &hasher
                )
                try hashRegularFile(
                    named: name,
                    directoryDescriptor: descriptor,
                    expected: pathMetadata,
                    hasher: &hasher,
                    deadline: deadline
                )
            default:
                // Symlinks, FIFOs, sockets, block/character devices, and all
                // other special objects are never opened or followed.
                throw AuditFailure.blocked
            }
        }
    }

    private func hashRegularFile(
        named name: String,
        directoryDescriptor: Int32,
        expected: stat,
        hasher: inout SHA256,
        deadline: AuditDeadline
    ) throws {
        let descriptor = openat(
            directoryDescriptor,
            name,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw AuditFailure.blocked }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              Self.sameIdentity(expected, opened),
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_nlink == 1 else {
            throw AuditFailure.blocked
        }
        var bytesRead: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try deadline.check()
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw AuditFailure.blocked
            }
            bytesRead += Int64(count)
            guard bytesRead <= limits.maximumFileBytes,
                  bytesRead <= Int64(expected.st_size) else {
                throw AuditFailure.oversize
            }
            hasher.update(data: Data(buffer.prefix(count)))
        }
        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              Self.sameIdentity(opened, after),
              bytesRead == Int64(expected.st_size) else {
            throw AuditFailure.blocked
        }
    }

    private static func isSafeProfileName(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 64
            && value != "."
            && value != ".."
            && value.allSatisfy {
                $0.isLetter || $0.isNumber || $0 == "." || $0 == "_" || $0 == "-"
            }
    }

    private static func isValidPluginName(_ name: String) -> Bool {
        let fullRange = NSRange(name.startIndex..., in: name)
        return allowedPluginName.firstMatch(in: name, range: fullRange)?.range == fullRange
    }

    private static func isSafePathComponent(_ value: String) -> Bool {
        !value.isEmpty
            && value != "."
            && value != ".."
            && !value.contains("/")
            && !value.contains("\0")
    }

    private static func sameIdentity(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev
            && first.st_ino == second.st_ino
            && first.st_mode == second.st_mode
            && first.st_nlink == second.st_nlink
            && first.st_size == second.st_size
            && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
            && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
    }

    private static func hashEntry(
        type: String,
        relative: String,
        metadata: stat,
        into hasher: inout SHA256
    ) {
        hashLengthPrefixed(Data(type.utf8), into: &hasher)
        hashLengthPrefixed(Data(relative.utf8), into: &hasher)
        hashLengthPrefixed(Data(String(metadata.st_mode & 0o7777, radix: 8).utf8), into: &hasher)
        hashLengthPrefixed(Data(String(metadata.st_size).utf8), into: &hasher)
    }

    private static func hashLengthPrefixed(_ data: Data, into hasher: inout SHA256) {
        var length = UInt64(data.count).bigEndian
        withUnsafeBytes(of: &length) { hasher.update(data: Data($0)) }
        hasher.update(data: data)
    }
}
