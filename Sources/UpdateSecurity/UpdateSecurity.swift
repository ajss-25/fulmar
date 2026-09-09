import Darwin
import Foundation
import Security

public struct SignedApplicationAttestation: Codable, Equatable, Sendable {
    public let identifier: String
    public let teamIdentifier: String
    public let cdHashHex: String
    public let version: String
    public let build: Int

    public init(
        identifier: String,
        teamIdentifier: String,
        cdHashHex: String,
        version: String,
        build: Int
    ) {
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.cdHashHex = cdHashHex
        self.version = version
        self.build = build
    }

    public func encodedArgument() throws -> String {
        try JSONEncoder().encode(self).base64EncodedString()
    }

    public static func decodeArgument(_ value: String) throws -> Self {
        guard value.utf8.count <= 4_096,
              let data = Data(base64Encoded: value),
              data.count <= 3_072 else {
            throw UpdateSecurityError.invalidAttestation
        }
        let decoded = try JSONDecoder().decode(Self.self, from: data)
        try decoded.validateShape()
        return decoded
    }

    public func validateShape() throws {
        guard identifier == "com.angadjairath.localharness",
              !teamIdentifier.isEmpty,
              teamIdentifier.utf8.count <= 128,
              !version.isEmpty,
              version.utf8.count <= 128,
              build > 0,
              cdHashHex.count >= 40,
              cdHashHex.count <= 128,
              cdHashHex.count.isMultiple(of: 2),
              cdHashHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw UpdateSecurityError.invalidAttestation
        }
    }
}

public struct UpdateFileIdentity: Codable, Equatable, Sendable {
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt16
    public let owner: UInt32

    fileprivate init(_ info: stat) {
        device = UInt64(truncatingIfNeeded: info.st_dev)
        inode = UInt64(info.st_ino)
        mode = UInt16(info.st_mode & 0o177777)
        owner = UInt32(info.st_uid)
    }

    public init(device: UInt64, inode: UInt64, mode: UInt16, owner: UInt32) {
        self.device = device
        self.inode = inode
        self.mode = mode
        self.owner = owner
    }
}

public struct ValidatedUpdateApplication: Codable, Equatable, Sendable {
    public let identity: UpdateFileIdentity
    public let attestation: SignedApplicationAttestation

    public init(identity: UpdateFileIdentity, attestation: SignedApplicationAttestation) {
        self.identity = identity
        self.attestation = attestation
    }
}

struct UpdateAutomaticBackupCandidate: Equatable {
    let url: URL
    let build: Int
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64
}

public enum UpdateSecurityError: Error, Equatable {
    case invalidAttestation
    case invalidPath
    case invalidTopology
    case signatureInvalid
    case bundleMetadataInvalid
    case applicationChanged
    case parentDidNotExit
    case installFailed
    case rollbackFailed
}

public enum UpdateApplicationSecurity {
    public static let expectedIdentifier = "com.angadjairath.localharness"
    public static let expectedApplicationBundleName = "Fulmar.app"
    /// Keep the rollback produced by the current update plus the two newest
    /// earlier, valid automatic rollback copies. Manually named recovery apps
    /// are never part of automatic retention.
    public static let automaticApplicationBackupRetentionCount = 3

    public static func strictAttestation(at app: URL) throws -> SignedApplicationAttestation {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode),
                nil
              ) == errSecSuccess else {
            throw UpdateSecurityError.signatureInvalid
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              identifier == expectedIdentifier,
              let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
              !team.isEmpty,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64 else {
            throw UpdateSecurityError.signatureInvalid
        }
        let metadata = try bundleMetadata(at: app)
        let attestation = SignedApplicationAttestation(
            identifier: identifier,
            teamIdentifier: team,
            cdHashHex: cdHash.map { String(format: "%02x", $0) }.joined(),
            version: metadata.version,
            build: metadata.build
        )
        try attestation.validateShape()
        return attestation
    }

    public static func stableValidatedApplication(
        at app: URL,
        expected: SignedApplicationAttestation
    ) throws -> ValidatedUpdateApplication {
        try expected.validateShape()
        let before = try directoryIdentity(at: app, requireCurrentUser: true)
        let actual = try strictAttestation(at: app)
        let after = try directoryIdentity(at: app, requireCurrentUser: true)
        guard before == after, actual == expected else {
            throw UpdateSecurityError.applicationChanged
        }
        return ValidatedUpdateApplication(identity: after, attestation: actual)
    }

    public static func executableURL(at app: URL) throws -> URL {
        let infoURL = app.appendingPathComponent("Contents/Info.plist", isDirectory: false)
        let data = try readBoundedRegularFile(infoURL, maximumBytes: 1_048_576)
        guard let values = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
              ) as? [String: Any],
              values["CFBundleIdentifier"] as? String == expectedIdentifier,
              let executableName = values["CFBundleExecutable"] as? String,
              !executableName.isEmpty,
              executableName.utf8.count <= 255,
              executableName == URL(fileURLWithPath: executableName).lastPathComponent,
              !executableName.contains("/") else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        let executable = app.appendingPathComponent(
            "Contents/MacOS/\(executableName)",
            isDirectory: false
        )
        try requireCanonical(executable)
        var metadata = stat()
        guard lstat(executable.path, &metadata) == 0,
              metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o111 != 0 else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        return executable
    }

    public static func validatePrivateStagedPath(_ staged: URL, updatesRoot: URL) throws {
        let updates = updatesRoot
        let support = updates.deletingLastPathComponent()
        let stagedBase = updates.appendingPathComponent("Staged", isDirectory: true)
        let expanded = staged.deletingLastPathComponent()
        let operation = expanded.deletingLastPathComponent()
        guard support.lastPathComponent == "Local Harness",
              updates.lastPathComponent == "Updates",
              isLexicallyNormalizedAbsolutePath(staged.path),
              isLexicallyNormalizedAbsolutePath(updates.path),
              staged.lastPathComponent == expectedApplicationBundleName,
              staged.pathExtension == "app",
              expanded.lastPathComponent == "Expanded",
              operation.deletingLastPathComponent() == stagedBase,
              UUID(uuidString: operation.lastPathComponent) != nil else {
            throw UpdateSecurityError.invalidPath
        }
        try validatePrivateDirectory(support)
        try validatePrivateDirectory(updates)
        try validatePrivateDirectory(stagedBase)
        try validatePrivateDirectory(operation)
        try validatePrivateDirectory(expanded)
        _ = try directoryIdentity(at: staged, requireCurrentUser: true)
        try requireCanonical(staged)
    }

    public static func preparePrivateBackupPath(_ backup: URL, updatesRoot: URL) throws {
        let updates = updatesRoot
        guard updates.lastPathComponent == "Updates",
              updates.deletingLastPathComponent().lastPathComponent == "Local Harness",
              isLexicallyNormalizedAbsolutePath(updates.path),
              isLexicallyNormalizedAbsolutePath(backup.path) else {
            throw UpdateSecurityError.invalidPath
        }
        // Releases before 1.2.15 created these owner-owned directories with
        // the process umask's 0755 mode. Tighten that exact legacy state
        // through an opened, no-follow directory descriptor before accepting
        // it. Writable-by-other-users, linked, foreign-owned, or replaced
        // directories still fail closed.
        try preparePrivateOwnedDirectory(updates.deletingLastPathComponent())
        try preparePrivateOwnedDirectory(updates)
        let parent = updates.appendingPathComponent("App Backups", isDirectory: true)
        var info = stat()
        if lstat(parent.path, &info) != 0 {
            guard errno == ENOENT, mkdir(parent.path, 0o700) == 0 else {
                throw UpdateSecurityError.invalidTopology
            }
        }
        try preparePrivateOwnedDirectory(parent)
        guard backup.deletingLastPathComponent().path == parent.path,
              backup.pathExtension == "app",
              !backup.lastPathComponent.isEmpty,
              backup.lastPathComponent.utf8.count <= 255,
              backup.lastPathComponent.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
              lstat(backup.path, &info) != 0,
              errno == ENOENT else {
            throw UpdateSecurityError.invalidPath
        }
    }

    /// Removes one exact private staging operation after first atomically
    /// quarantining its already-opened inode under another UUID in the same
    /// directory. The top-level operation itself must be a canonical
    /// owner-only directory; nested links are removed as links, never followed.
    public static func discardPrivateStagedOperation(
        stagedApplication: URL,
        updatesRoot: URL
    ) throws {
        try discardPrivateStagedOperation(
            stagedApplication: stagedApplication,
            updatesRoot: updatesRoot,
            afterValidationForTesting: nil
        )
    }

    static func discardPrivateStagedOperation(
        stagedApplication: URL,
        updatesRoot: URL,
        afterValidationForTesting: (() throws -> Void)?
    ) throws {
        let updates = updatesRoot
        let stagedBase = updates.appendingPathComponent("Staged", isDirectory: true)
        let expanded = stagedApplication.deletingLastPathComponent()
        let operation = expanded.deletingLastPathComponent()
        guard updates.lastPathComponent == "Updates",
              updates.deletingLastPathComponent().lastPathComponent == "Local Harness",
              stagedApplication.lastPathComponent == expectedApplicationBundleName,
              stagedApplication.pathExtension == "app",
              expanded.lastPathComponent == "Expanded",
              operation.deletingLastPathComponent().path == stagedBase.path,
              UUID(uuidString: operation.lastPathComponent) != nil,
              isLexicallyNormalizedAbsolutePath(stagedApplication.path),
              isLexicallyNormalizedAbsolutePath(updates.path) else {
            throw UpdateSecurityError.invalidPath
        }
        try preparePrivateOwnedDirectory(updates.deletingLastPathComponent())
        try preparePrivateOwnedDirectory(updates)
        try preparePrivateOwnedDirectory(stagedBase)
        try validatePrivateDirectory(operation)
        let expected = try directoryIdentity(at: operation, requireCurrentUser: true)
        try afterValidationForTesting?()

        var quarantine: URL
        var quarantineInfo = stat()
        repeat {
            quarantine = stagedBase.appendingPathComponent(UUID().uuidString, isDirectory: true)
        } while lstat(quarantine.path, &quarantineInfo) == 0
        guard errno == ENOENT,
              rename(operation.path, quarantine.path) == 0 else {
            throw UpdateSecurityError.invalidTopology
        }
        var moved = true
        defer {
            if moved {
                var sourceInfo = stat()
                if lstat(operation.path, &sourceInfo) != 0, errno == ENOENT {
                    _ = rename(quarantine.path, operation.path)
                }
            }
        }
        let quarantined = try directoryIdentity(at: quarantine, requireCurrentUser: true)
        guard quarantined == expected else {
            throw UpdateSecurityError.applicationChanged
        }
        try requireCanonical(quarantine)
        do {
            try FileManager.default.removeItem(at: quarantine)
            moved = false
        } catch {
            throw UpdateSecurityError.invalidTopology
        }
    }

    /// Removes only the exact empty containers left after the staged app has
    /// been moved into place. Unexpected files leave the operation intact for
    /// the next conservative orphan sweep.
    public static func removeEmptyPrivateStagedOperation(
        stagedApplication: URL,
        updatesRoot: URL
    ) throws {
        let updates = updatesRoot
        let stagedBase = updates.appendingPathComponent("Staged", isDirectory: true)
        let expanded = stagedApplication.deletingLastPathComponent()
        let operation = expanded.deletingLastPathComponent()
        guard stagedApplication.lastPathComponent == expectedApplicationBundleName,
              expanded.lastPathComponent == "Expanded",
              operation.deletingLastPathComponent().path == stagedBase.path,
              UUID(uuidString: operation.lastPathComponent) != nil else {
            throw UpdateSecurityError.invalidPath
        }
        try validatePrivateDirectory(updates.deletingLastPathComponent())
        try validatePrivateDirectory(updates)
        try validatePrivateDirectory(stagedBase)
        try validatePrivateDirectory(operation)
        try validatePrivateDirectory(expanded)
        guard try FileManager.default.contentsOfDirectory(atPath: expanded.path).isEmpty,
              rmdir(expanded.path) == 0,
              rmdir(operation.path) == 0 else {
            throw UpdateSecurityError.invalidTopology
        }
    }

    /// Best-effort pruning for helper-created rollback apps. A candidate is
    /// eligible only when its strict filename build, owner, inode, bundle ID,
    /// Developer Team, nested signature and actual build all agree. Invalid,
    /// manual or raced entries are left untouched.
    @discardableResult
    public static func pruneAutomaticApplicationBackups(
        updatesRoot: URL,
        preserving currentRollback: URL,
        teamIdentifier: String
    ) -> Int {
        guard !teamIdentifier.isEmpty else { return 0 }
        let parent = updatesRoot.appendingPathComponent("App Backups", isDirectory: true)
        do {
            try preparePrivateOwnedDirectory(updatesRoot.deletingLastPathComponent())
            try preparePrivateOwnedDirectory(updatesRoot)
            try preparePrivateOwnedDirectory(parent)
        } catch { return 0 }
        guard currentRollback.deletingLastPathComponent().path == parent.path else { return 0 }

        let names: [String]
        do { names = try FileManager.default.contentsOfDirectory(atPath: parent.path) }
        catch { return 0 }
        var validated: [(candidate: UpdateAutomaticBackupCandidate, application: ValidatedUpdateApplication)] = []
        for name in names {
            guard let namedBuild = automaticBackupBuild(from: name) else { continue }
            let url = parent.appendingPathComponent(name, isDirectory: true)
            do {
                let attestation = try strictAttestation(at: url)
                guard attestation.identifier == expectedIdentifier,
                      attestation.teamIdentifier == teamIdentifier,
                      attestation.build == namedBuild else { continue }
                let application = try stableValidatedApplication(at: url, expected: attestation)
                var info = stat()
                guard lstat(url.path, &info) == 0 else { continue }
                validated.append((
                    UpdateAutomaticBackupCandidate(
                        url: url,
                        build: namedBuild,
                        modifiedSeconds: Int64(info.st_mtimespec.tv_sec),
                        modifiedNanoseconds: Int64(info.st_mtimespec.tv_nsec)
                    ),
                    application
                ))
            } catch { continue }
        }
        let victims = automaticBackupVictims(
            candidates: validated.map(\.candidate),
            preserving: currentRollback,
            retentionCount: automaticApplicationBackupRetentionCount
        )
        guard !victims.isEmpty else { return 0 }
        let byPath = Dictionary(uniqueKeysWithValues: validated.map { ($0.candidate.url.path, $0.application) })
        var removed = 0
        for victim in victims {
            guard let expected = byPath[victim.url.path],
                  (try? stableValidatedApplication(at: victim.url, expected: expected.attestation)) == expected else {
                continue
            }
            let quarantine = parent.appendingPathComponent(
                "Fulmar backup build \(victim.build) \(UUID().uuidString).app",
                isDirectory: true
            )
            guard rename(victim.url.path, quarantine.path) == 0 else { continue }
            var restore = true
            defer {
                if restore {
                    var originalInfo = stat()
                    if lstat(victim.url.path, &originalInfo) != 0, errno == ENOENT {
                        _ = rename(quarantine.path, victim.url.path)
                    }
                }
            }
            guard (try? stableValidatedApplication(at: quarantine, expected: expected.attestation)) == expected else {
                continue
            }
            do {
                try FileManager.default.removeItem(at: quarantine)
                restore = false
                removed += 1
            } catch { continue }
        }
        return removed
    }

    static func automaticBackupBuild(from name: String) -> Int? {
        let prefix = "Fulmar backup build "
        let suffix = ".app"
        guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { return nil }
        let body = name.dropFirst(prefix.count).dropLast(suffix.count)
        let fields = body.split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 2,
              let build = Int(fields[0]), build > 0,
              UUID(uuidString: String(fields[1])) != nil else { return nil }
        return build
    }

    static func automaticBackupVictims(
        candidates: [UpdateAutomaticBackupCandidate],
        preserving currentRollback: URL,
        retentionCount: Int
    ) -> [UpdateAutomaticBackupCandidate] {
        guard retentionCount >= 1,
              candidates.contains(where: { $0.url.path == currentRollback.path }) else { return [] }
        let ordered = candidates.sorted {
            if $0.modifiedSeconds != $1.modifiedSeconds { return $0.modifiedSeconds > $1.modifiedSeconds }
            if $0.modifiedNanoseconds != $1.modifiedNanoseconds { return $0.modifiedNanoseconds > $1.modifiedNanoseconds }
            return $0.url.path < $1.url.path
        }
        var kept: Set<String> = [currentRollback.path]
        for candidate in ordered where kept.count < retentionCount {
            kept.insert(candidate.url.path)
        }
        return ordered.filter { !kept.contains($0.url.path) }
    }

    public static func directoryIdentity(
        at directory: URL,
        requireCurrentUser: Bool
    ) throws -> UpdateFileIdentity {
        var info = stat()
        guard directory.isFileURL,
              lstat(directory.path, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              !requireCurrentUser || info.st_uid == geteuid() else {
            throw UpdateSecurityError.invalidTopology
        }
        return UpdateFileIdentity(info)
    }

    public static func validatePrivateDirectory(_ directory: URL) throws {
        var info = stat()
        guard lstat(directory.path, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              info.st_uid == geteuid(),
              info.st_mode & 0o7777 == 0o700 else {
            throw UpdateSecurityError.invalidTopology
        }
        try requireCanonical(directory)
    }

    /// Tightens a canonical, current-user-owned directory left by an older
    /// release to the updater's exact 0700 policy without trusting a pathname
    /// across the chmod boundary. This intentionally accepts read/search bits
    /// for group or other only; any write or special bit remains a hard error.
    public static func preparePrivateOwnedDirectory(_ directory: URL) throws {
        try preparePrivateOwnedDirectory(directory, afterOpeningForTesting: nil)
    }

    /// Internal deterministic race seam. Production callers always use the
    /// public overload above; tests can replace the pathname only after the
    /// no-follow descriptor and its inode have been captured.
    static func preparePrivateOwnedDirectory(
        _ directory: URL,
        afterOpeningForTesting: ((Int32) throws -> Void)?
    ) throws {
        guard directory.isFileURL,
              isLexicallyNormalizedAbsolutePath(directory.path) else {
            throw UpdateSecurityError.invalidPath
        }
        try requireCanonical(directory)

        var before = stat()
        guard lstat(directory.path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              before.st_uid == geteuid() else {
            throw UpdateSecurityError.invalidTopology
        }
        let originalPermissions = before.st_mode & 0o7777
        guard originalPermissions & 0o7022 == 0,
              originalPermissions & 0o0700 == 0o0700 else {
            throw UpdateSecurityError.invalidTopology
        }

        let descriptor = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdateSecurityError.invalidTopology }
        defer { Darwin.close(descriptor) }

        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              sameDirectoryNode(before, opened) else {
            throw UpdateSecurityError.invalidTopology
        }
        try afterOpeningForTesting?(descriptor)
        if opened.st_mode & 0o7777 != 0o700 {
            guard fchmod(descriptor, 0o700) == 0 else {
                throw UpdateSecurityError.invalidTopology
            }
        }

        var secured = stat()
        var pathAfter = stat()
        guard fstat(descriptor, &secured) == 0,
              lstat(directory.path, &pathAfter) == 0,
              sameDirectoryNode(opened, secured),
              sameDirectoryNode(secured, pathAfter),
              secured.st_mode & 0o7777 == 0o700,
              pathAfter.st_mode & 0o7777 == 0o700 else {
            throw UpdateSecurityError.invalidTopology
        }
        try requireCanonical(directory)
    }

    public static func requireCanonical(_ url: URL) throws {
        guard url.isFileURL,
              isLexicallyNormalizedAbsolutePath(url.path),
              let resolved = realpath(url.path, nil) else {
            throw UpdateSecurityError.invalidPath
        }
        defer { free(resolved) }
        guard String(cString: resolved) == url.path else {
            throw UpdateSecurityError.invalidPath
        }
    }

    private static func isLexicallyNormalizedAbsolutePath(_ path: String) -> Bool {
        guard path.hasPrefix("/"),
              path.utf8.count <= 4_096,
              !path.contains("\\"),
              path == path.precomposedStringWithCanonicalMapping else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return components.first?.isEmpty == true
            && components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    }

    private static func sameDirectoryNode(_ left: stat, _ right: stat) -> Bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && left.st_uid == right.st_uid
            && left.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
            && right.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR)
    }

    private static func bundleMetadata(at app: URL) throws -> (version: String, build: Int) {
        let infoURL = app.appendingPathComponent("Contents/Info.plist", isDirectory: false)
        let data = try readBoundedRegularFile(infoURL, maximumBytes: 1_048_576)
        guard let values = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
              ) as? [String: Any],
              values["CFBundleIdentifier"] as? String == expectedIdentifier,
              let version = values["CFBundleShortVersionString"] as? String,
              !version.isEmpty,
              let buildText = values["CFBundleVersion"] as? String,
              let build = Int(buildText),
              build > 0 else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        return (version, build)
    }

    private static func readBoundedRegularFile(_ file: URL, maximumBytes: Int) throws -> Data {
        try requireCanonical(file)
        var before = stat()
        guard maximumBytes > 0,
              lstat(file.path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_uid == geteuid(),
              before.st_nlink == 1,
              before.st_size >= 0,
              before.st_size <= off_t(maximumBytes) else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        let descriptor = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw UpdateSecurityError.bundleMetadataInvalid }
        defer { Darwin.close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              UpdateFileIdentity(before) == UpdateFileIdentity(opened),
              before.st_size == opened.st_size else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        var data = Data(count: Int(opened.st_size))
        var consumed = 0
        while consumed < data.count {
            let remaining = data.count - consumed
            let result: Int = data.withUnsafeMutableBytes { bytes in
                guard let base = bytes.baseAddress else { return 0 }
                return pread(
                    descriptor,
                    base.advanced(by: consumed),
                    remaining,
                    off_t(consumed)
                )
            }
            if result < 0, errno == EINTR { continue }
            guard result > 0 else { throw UpdateSecurityError.bundleMetadataInvalid }
            consumed += result
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0,
              UpdateFileIdentity(opened) == UpdateFileIdentity(after),
              opened.st_size == after.st_size,
              opened.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              opened.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              opened.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              opened.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw UpdateSecurityError.bundleMetadataInvalid
        }
        return data
    }
}

public struct UpdateInstallTransactionHooks {
    public var waitForParentExit: () throws -> Void
    public var validateCurrent: () throws -> ValidatedUpdateApplication
    public var validateStaged: () throws -> ValidatedUpdateApplication
    public var prepareBackup: () throws -> Void
    public var createNonce: () throws -> String
    public var beginJournal: (
        _ current: ValidatedUpdateApplication,
        _ candidate: ValidatedUpdateApplication,
        _ nonceHex: String
    ) throws -> Void
    public var persistJournalPhase: (UpdateInstallJournalPhase) throws -> Void
    public var retireJournal: () throws -> Void
    public var moveCurrentToBackup: () throws -> Void
    public var validateBackup: () throws -> ValidatedUpdateApplication
    public var moveStagedToCurrent: () throws -> Void
    public var validateInstalled: () throws -> ValidatedUpdateApplication
    public var removeInstalled: () throws -> Void
    public var restoreBackup: () throws -> Void
    public var validateRestored: () throws -> ValidatedUpdateApplication
    public var launchInstalled: (_ nonceHex: String) throws -> pid_t
    public var awaitInstalledHealth: (
        _ processIdentifier: pid_t,
        _ nonceHex: String,
        _ candidate: ValidatedUpdateApplication
    ) throws -> Void
    public var stopInstalled: (_ processIdentifier: pid_t) throws -> Void

    public init(
        waitForParentExit: @escaping () throws -> Void,
        validateCurrent: @escaping () throws -> ValidatedUpdateApplication,
        validateStaged: @escaping () throws -> ValidatedUpdateApplication,
        prepareBackup: @escaping () throws -> Void,
        createNonce: @escaping () throws -> String,
        beginJournal: @escaping (
            _ current: ValidatedUpdateApplication,
            _ candidate: ValidatedUpdateApplication,
            _ nonceHex: String
        ) throws -> Void,
        persistJournalPhase: @escaping (UpdateInstallJournalPhase) throws -> Void,
        retireJournal: @escaping () throws -> Void,
        moveCurrentToBackup: @escaping () throws -> Void,
        validateBackup: @escaping () throws -> ValidatedUpdateApplication,
        moveStagedToCurrent: @escaping () throws -> Void,
        validateInstalled: @escaping () throws -> ValidatedUpdateApplication,
        removeInstalled: @escaping () throws -> Void,
        restoreBackup: @escaping () throws -> Void,
        validateRestored: @escaping () throws -> ValidatedUpdateApplication,
        launchInstalled: @escaping (_ nonceHex: String) throws -> pid_t,
        awaitInstalledHealth: @escaping (
            _ processIdentifier: pid_t,
            _ nonceHex: String,
            _ candidate: ValidatedUpdateApplication
        ) throws -> Void,
        stopInstalled: @escaping (_ processIdentifier: pid_t) throws -> Void
    ) {
        self.waitForParentExit = waitForParentExit
        self.validateCurrent = validateCurrent
        self.validateStaged = validateStaged
        self.prepareBackup = prepareBackup
        self.createNonce = createNonce
        self.beginJournal = beginJournal
        self.persistJournalPhase = persistJournalPhase
        self.retireJournal = retireJournal
        self.moveCurrentToBackup = moveCurrentToBackup
        self.validateBackup = validateBackup
        self.moveStagedToCurrent = moveStagedToCurrent
        self.validateInstalled = validateInstalled
        self.removeInstalled = removeInstalled
        self.restoreBackup = restoreBackup
        self.validateRestored = validateRestored
        self.launchInstalled = launchInstalled
        self.awaitInstalledHealth = awaitInstalledHealth
        self.stopInstalled = stopInstalled
    }
}

public enum UpdateInstallTransaction {
    public static func execute(
        expectedCurrent: SignedApplicationAttestation,
        expectedStaged: SignedApplicationAttestation,
        hooks: UpdateInstallTransactionHooks
    ) throws {
        try expectedCurrent.validateShape()
        try expectedStaged.validateShape()
        try hooks.waitForParentExit()

        let current = try hooks.validateCurrent()
        let staged = try hooks.validateStaged()
        guard current.attestation == expectedCurrent,
              staged.attestation == expectedStaged,
              current.identity.device == staged.identity.device else {
            throw UpdateSecurityError.applicationChanged
        }
        try hooks.prepareBackup()
        let nonceHex = try hooks.createNonce()
        guard nonceHex.count == 64,
              nonceHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw UpdateInstallJournalError.invalidJournal
        }
        try hooks.beginJournal(current, staged, nonceHex)

        var movedCurrent = false
        var movedStaged = false
        var launchedProcess: pid_t?
        var commitDecisionDurable = false
        do {
            try hooks.moveCurrentToBackup()
            movedCurrent = true
            let backup = try hooks.validateBackup()
            guard backup == current else { throw UpdateSecurityError.applicationChanged }
            try hooks.persistJournalPhase(.rollbackRetained)

            // This second staged validation is deliberately adjacent to the
            // move. It catches replacement during the parent wait or while the
            // current app was moved aside.
            let moveBoundary = try hooks.validateStaged()
            guard moveBoundary == staged else { throw UpdateSecurityError.applicationChanged }
            try hooks.moveStagedToCurrent()
            movedStaged = true
            try hooks.persistJournalPhase(.candidateInstalled)

            // rename(2) has no compare-by-inode primitive on macOS. Validate
            // both the moved inode and full nested signature at the destination
            // before anything is launched; a last-instruction path swap is
            // therefore removed and rolled back, never executed.
            let installed = try hooks.validateInstalled()
            guard installed == moveBoundary,
                  installed.attestation == expectedStaged else {
                throw UpdateSecurityError.applicationChanged
            }
            let processIdentifier = try hooks.launchInstalled(nonceHex)
            guard processIdentifier > 1 else { throw UpdateSecurityError.installFailed }
            launchedProcess = processIdentifier
            try hooks.awaitInstalledHealth(processIdentifier, nonceHex, installed)
            // The acknowledgement is bound to the direct child PID and nonce,
            // then the destination inode/signature is checked once more before
            // a durable commit decision can be recorded.
            guard try hooks.validateInstalled() == installed else {
                throw UpdateSecurityError.applicationChanged
            }
            try hooks.persistJournalPhase(.healthAcknowledged)
            commitDecisionDurable = true
            try hooks.persistJournalPhase(.committed)
            try hooks.retireJournal()
        } catch {
            // Once authenticated health is durable, replay must finish commit;
            // rolling back here would make the same journal choose two results.
            if commitDecisionDurable { throw error }
            if let launchedProcess {
                do { try hooks.stopInstalled(launchedProcess) }
                catch { throw UpdateSecurityError.rollbackFailed }
            }
            guard movedCurrent else { throw error }
            try? hooks.persistJournalPhase(.rollingBack)
            if movedStaged { try? hooks.removeInstalled() }
            do {
                try hooks.restoreBackup()
                let restored = try hooks.validateRestored()
                guard restored == current,
                      restored.attestation == expectedCurrent else {
                    throw UpdateSecurityError.rollbackFailed
                }
                try hooks.retireJournal()
            } catch {
                throw UpdateSecurityError.rollbackFailed
            }
            throw error
        }
    }
}
