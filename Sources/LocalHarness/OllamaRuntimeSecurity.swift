import Darwin
import Foundation
import Security

struct OllamaExecutableIdentity: Equatable, Sendable {
    let executableURL: URL
    let device: UInt64
    let inode: UInt64
    let byteCount: Int64
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64
    let permissions: UInt16
    let owner: UInt32
    let codeIdentifier: String
    let teamIdentifier: String
    let cdHashHex: String
}

enum OllamaRuntimeSecurityError: Error, LocalizedError, Equatable {
    case executableNotFound
    case executableUntrusted
    case executableChanged
    case unsafeModelStore
    case unsafePrivateDirectory

    var errorDescription: String? {
        switch self {
        case .executableNotFound:
            return "The official Ollama app is not installed. Install the signed macOS release and try again."
        case .executableUntrusted:
            return "The installed Ollama executable has an unexpected signature, owner, path, or permissions."
        case .executableChanged:
            return "The Ollama executable changed while the local runtime was starting."
        case .unsafeModelStore:
            return "The Ollama model store contains an unsafe link, file type, owner, or writable entry."
        case .unsafePrivateDirectory:
            return "The private Ollama runtime directory could not be secured."
        }
    }
}

/// Product boundary for model-store locations. The runtime validator already
/// accepts an explicit directory for isolated qualification, but the shipping
/// UI does not yet persist a user-selected security-scoped folder or coordinate
/// its replacement through the protected stop/restart transaction.
enum OllamaModelStoreConfigurationError: Error, LocalizedError, Equatable, Sendable {
    case userSelectionUnavailable

    var errorDescription: String? {
        switch self {
        case .userSelectionUnavailable:
            return "This Fulmar release uses the current macOS account's standard Ollama model store. Choosing a different model-store folder is not yet supported in the app."
        }
    }
}

/// Resolves every supported launcher spelling to one canonical, official
/// Ollama executable identity. The application bundle is preferred; fixed
/// package-manager shims are accepted only when they resolve to the same signed
/// official code. Ambient PATH is never consulted.
enum OllamaExecutableTrust {
    static let expectedIdentifier = "ai.ollama.ollama"
    static let expectedTeamIdentifier = "3MU9H2V9Y9"
    private static let systemApplicationCandidate = "/Applications/Ollama.app/Contents/Resources/ollama"
    private static let packageManagerCandidates = [
        "/usr/local/bin/ollama", "/opt/homebrew/bin/ollama"
    ]

    /// Fixed candidates derived from the authenticated POSIX account record.
    /// Environment variables and ambient PATH never participate. Keeping this
    /// builder internal makes the portability boundary deterministic in tests.
    static func candidatePaths(posixHomePath: String?) -> [String] {
        var candidates = [systemApplicationCandidate]
        if let posixHomePath,
           !posixHomePath.isEmpty,
           !posixHomePath.contains("\0"),
           posixHomePath.hasPrefix("/") {
            let home = URL(fileURLWithPath: posixHomePath, isDirectory: true).standardizedFileURL
            if home.path != "/", home.path == posixHomePath {
                candidates.append(
                    home.appendingPathComponent("Applications", isDirectory: true)
                        .appendingPathComponent("Ollama.app", isDirectory: true)
                        .appendingPathComponent("Contents", isDirectory: true)
                        .appendingPathComponent("Resources", isDirectory: true)
                        .appendingPathComponent("ollama", isDirectory: false).path
                )
            }
        }
        candidates.append(contentsOf: packageManagerCandidates)
        return candidates
    }

    static var fixedCandidates: [String] {
        candidatePaths(posixHomePath: currentPOSIXHomePath())
    }

    /// Returns the authenticated account's home directory without consulting
    /// mutable process environment. The same account record is used for the
    /// per-user app candidate and the standard Ollama model-store default.
    static func currentPOSIXHomeDirectory() -> URL? {
        currentPOSIXHomePath().map { URL(fileURLWithPath: $0, isDirectory: true) }
    }

    static func resolve() throws -> OllamaExecutableIdentity {
        let candidates = fixedCandidates
        var foundCandidate = false
        for path in candidates {
            var candidateMetadata = stat()
            guard Darwin.lstat(path, &candidateMetadata) == 0 else { continue }
            foundCandidate = true
            if let identity = try? attest(
                candidate: URL(fileURLWithPath: path),
                allowedCandidatePaths: candidates
            ) { return identity }
        }
        throw foundCandidate ? OllamaRuntimeSecurityError.executableUntrusted : .executableNotFound
    }

    static func revalidate(_ expected: OllamaExecutableIdentity) throws {
        let actual = try attestCanonical(expected.executableURL)
        guard actual == expected else { throw OllamaRuntimeSecurityError.executableChanged }
    }

    /// Cheap final main-thread TOCTOU check used immediately before spawn.
    /// The expensive signature/CDHash verification produced `expected` on the
    /// serialized worker; post-spawn guest-code attestation remains mandatory.
    static func revalidateFilesystemIdentity(_ expected: OllamaExecutableIdentity) throws {
        try validateCanonicalAncestry(expected.executableURL)
        var metadata = stat()
        guard Darwin.lstat(expected.executableURL.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_nlink == 1,
              metadata.st_uid == expected.owner,
              metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0,
              UInt64(truncatingIfNeeded: metadata.st_dev) == expected.device,
              UInt64(metadata.st_ino) == expected.inode,
              metadata.st_size == expected.byteCount,
              Int64(metadata.st_mtimespec.tv_sec) == expected.modifiedSeconds,
              Int64(metadata.st_mtimespec.tv_nsec) == expected.modifiedNanoseconds,
              UInt16(metadata.st_mode & 0o7777) == expected.permissions else {
            throw OllamaRuntimeSecurityError.executableChanged
        }
    }

    static func process(_ processIdentifier: Int32, matches expected: OllamaExecutableIdentity) -> Bool {
        guard processIdentifier > 0 else { return false }
        var buffer = [CChar](repeating: 0, count: 4_096)
        let length = proc_pidpath(processIdentifier, &buffer, UInt32(buffer.count))
        guard length > 0 else { return false }
        let runningPath = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().standardizedFileURL
        guard runningPath == expected.executableURL else { return false }
        guard let requirement = makeRequirement(cdHashHex: expected.cdHashHex) else { return false }
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: processIdentifier)] as CFDictionary
        var runningCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &runningCode) == errSecSuccess,
              let runningCode,
              SecCodeCheckValidity(runningCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            return false
        }
        return (try? revalidate(expected)) != nil
    }

    private static func attest(
        candidate: URL,
        allowedCandidatePaths: [String]
    ) throws -> OllamaExecutableIdentity {
        guard candidate.isFileURL,
              candidate.path.hasPrefix("/"),
              !candidate.path.contains("\0"),
              allowedCandidatePaths.contains(candidate.path),
              let resolved = candidate.path.withCString({ Darwin.realpath($0, nil) }) else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }
        defer { free(resolved) }
        let canonical = URL(fileURLWithPath: String(cString: resolved)).standardizedFileURL
        return try attestCanonical(canonical)
    }

    /// `getpwuid_r` is used instead of `HOME` or Foundation's process-derived
    /// home lookup so a launched app cannot be redirected to another account's
    /// bundle candidate. The bounded retry handles unusually large directory
    /// service records without permitting unbounded allocation.
    private static func currentPOSIXHomePath() -> String? {
        var capacity = 16_384
        while capacity <= 1_048_576 {
            var record = passwd()
            var result: UnsafeMutablePointer<passwd>?
            var buffer = [CChar](repeating: 0, count: capacity)
            let status = getpwuid_r(geteuid(), &record, &buffer, buffer.count, &result)
            if status == ERANGE {
                capacity *= 2
                continue
            }
            guard status == 0,
                  result != nil,
                  record.pw_uid == geteuid(),
                  let directory = record.pw_dir else { return nil }
            let path = String(cString: directory)
            guard !path.isEmpty, path.utf8.count < Int(PATH_MAX) else { return nil }
            return path
        }
        return nil
    }

    private static func attestCanonical(_ canonical: URL) throws -> OllamaExecutableIdentity {
        guard canonical.isFileURL,
              canonical.path.hasPrefix("/"),
              !canonical.path.contains("\0") else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }
        try validateCanonicalAncestry(canonical)

        var before = stat()
        guard Darwin.lstat(canonical.path, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_nlink == 1,
              before.st_uid == 0 || before.st_uid == geteuid(),
              before.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              before.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0 else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }

        guard let requirement = makeRequirement() else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(canonical as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
                requirement
              ) == errSecSuccess else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let values = information as? [String: Any],
              values[kSecCodeInfoIdentifier as String] as? String == expectedIdentifier,
              values[kSecCodeInfoTeamIdentifier as String] as? String == expectedTeamIdentifier,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64 else {
            throw OllamaRuntimeSecurityError.executableUntrusted
        }

        var after = stat()
        guard Darwin.lstat(canonical.path, &after) == 0,
              stableIdentity(before) == stableIdentity(after) else {
            throw OllamaRuntimeSecurityError.executableChanged
        }
        return OllamaExecutableIdentity(
            executableURL: canonical,
            device: UInt64(truncatingIfNeeded: after.st_dev),
            inode: UInt64(after.st_ino),
            byteCount: after.st_size,
            modifiedSeconds: Int64(after.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(after.st_mtimespec.tv_nsec),
            permissions: UInt16(after.st_mode & 0o7777),
            owner: UInt32(after.st_uid),
            codeIdentifier: expectedIdentifier,
            teamIdentifier: expectedTeamIdentifier,
            cdHashHex: cdHash.map { String(format: "%02x", $0) }.joined()
        )
    }

    private static func validateCanonicalAncestry(_ executable: URL) throws {
        var cursor = executable.deletingLastPathComponent()
        while true {
            var metadata = stat()
            guard Darwin.lstat(cursor.path, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0 || metadata.st_uid == geteuid(),
                  metadata.st_mode & S_IWOTH == 0 else {
                throw OllamaRuntimeSecurityError.executableUntrusted
            }
            if cursor.path == "/" { break }
            let parent = cursor.deletingLastPathComponent()
            guard parent.path != cursor.path else { throw OllamaRuntimeSecurityError.executableUntrusted }
            cursor = parent
        }
    }

    private static func stableIdentity(_ metadata: stat) -> [Int64] {
        [
            Int64(metadata.st_dev), Int64(bitPattern: metadata.st_ino), Int64(metadata.st_mode),
            Int64(metadata.st_uid), Int64(metadata.st_nlink), metadata.st_size,
            Int64(metadata.st_mtimespec.tv_sec), Int64(metadata.st_mtimespec.tv_nsec)
        ]
    }

    private static func makeRequirement(cdHashHex: String? = nil) -> SecRequirement? {
        var text = "identifier \"\(expectedIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(expectedTeamIdentifier)\""
        if let cdHashHex {
            guard cdHashHex.count >= 40,
                  cdHashHex.count <= 128,
                  cdHashHex.count.isMultiple(of: 2),
                  cdHashHex.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { return nil }
            text += " and cdhash H\"\(cdHashHex)\""
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else {
            return nil
        }
        return requirement
    }
}

struct AppOwnedOllamaSandbox: Equatable, Sendable {
    struct ModelStoreIdentity: Equatable, Sendable {
        let device: UInt64
        let inode: UInt64
        let owner: UInt32
        let permissions: UInt16
    }

    struct ModelStoreValidationLimits: Equatable, Sendable {
        var maximumEntries = 100_000
        var maximumDepth = 64
        var maximumRelativePathBytes = 4_096
        var duration: TimeInterval = 10

        static let production = ModelStoreValidationLimits()
    }

    let runtimeRoot: URL
    let homeDirectory: URL
    let temporaryDirectory: URL
    let modelStore: URL
    let modelStoreIdentity: ModelStoreIdentity
    let profile: String

    static func prepare(
        applicationSupport: URL,
        modelStoreDirectory: URL? = nil,
        modelStoreLimits: ModelStoreValidationLimits = .production,
        cancellationCheck: @escaping () throws -> Void = {},
        now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) throws -> AppOwnedOllamaSandbox {
        try cancellationCheck()
        let runtimeRoot = applicationSupport.appendingPathComponent("OllamaRuntime", isDirectory: true)
        let home = runtimeRoot.appendingPathComponent("Home", isDirectory: true)
        let temporary = runtimeRoot.appendingPathComponent("Temporary", isDirectory: true)
        try secureDirectory(runtimeRoot)
        try cancellationCheck()
        try secureDirectory(home)
        try cancellationCheck()
        try secureDirectory(temporary)

        let configuredStore: URL
        if let modelStoreDirectory {
            configuredStore = modelStoreDirectory
        } else {
            guard let accountHome = OllamaExecutableTrust.currentPOSIXHomeDirectory() else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            configuredStore = accountHome
                .appendingPathComponent(".ollama", isDirectory: true)
                .appendingPathComponent("models", isDirectory: true)
        }
        let validated = try validatedModelStore(
            configuredStore,
            limits: modelStoreLimits,
            cancellationCheck: cancellationCheck,
            now: now
        )
        return AppOwnedOllamaSandbox(
            runtimeRoot: runtimeRoot,
            homeDirectory: home,
            temporaryDirectory: temporary,
            modelStore: validated.url,
            modelStoreIdentity: validated.identity,
            profile: makeProfile(runtimeRoot: runtimeRoot, modelStore: validated.url)
        )
    }

    private static func secureDirectory(_ url: URL) throws {
        var metadata = stat()
        if Darwin.lstat(url.path, &metadata) != 0 {
            do {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
                try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
            } catch {
                throw OllamaRuntimeSecurityError.unsafePrivateDirectory
            }
        }
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o777 == 0o700 else {
            throw OllamaRuntimeSecurityError.unsafePrivateDirectory
        }
    }

    static func validateModelStore(
        _ configured: URL,
        limits: ModelStoreValidationLimits = .production,
        cancellationCheck: @escaping () throws -> Void = {},
        now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) throws -> URL {
        try validatedModelStore(
            configured,
            limits: limits,
            cancellationCheck: cancellationCheck,
            now: now
        ).url
    }

    func revalidateModelStoreIdentity() throws {
        let descriptor = try Self.openNoFollowDirectory(at: modelStore)
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              Self.isSafeModelDirectory(metadata),
              Self.identity(metadata) == modelStoreIdentity else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
    }

    private struct ModelStoreTraversalBudget {
        let limits: ModelStoreValidationLimits
        let deadline: UInt64
        let now: () -> UInt64
        let cancellationCheck: () throws -> Void
        var entries = 0

        mutating func checkpoint() throws {
            try cancellationCheck()
            guard now() <= deadline else { throw RuntimeStartupPrerequisiteError.timedOut }
        }

        mutating func consume(relativePath: String, depth: Int) throws {
            try checkpoint()
            entries += 1
            guard entries <= limits.maximumEntries,
                  depth <= limits.maximumDepth,
                  relativePath.utf8.count <= limits.maximumRelativePathBytes else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
        }
    }

    private static func validatedModelStore(
        _ configured: URL,
        limits: ModelStoreValidationLimits,
        cancellationCheck: @escaping () throws -> Void,
        now: @escaping () -> UInt64
    ) throws -> (url: URL, identity: ModelStoreIdentity) {
        guard configured.isFileURL,
              configured.path.hasPrefix("/"),
              !configured.path.contains("\0"),
              configured.path.utf8.count <= 4_096,
              limits.maximumEntries >= 0,
              limits.maximumDepth >= 0,
              limits.maximumRelativePathBytes > 0 else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        // Foundation's `standardizedFileURL` resolves an existing `/private/tmp`
        // path through the `/tmp` compatibility symlink.  Resolving anything
        // before the descriptor-relative walk defeats the no-follow contract,
        // so validate the spelling lexically and retain the declared path.
        _ = try absolutePathComponents(of: configured)
        let canonical = configured
        let descriptor = try openNoFollowDirectory(at: canonical)
        defer { _ = Darwin.close(descriptor) }
        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              isSafeModelDirectory(before) else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }

        let start = now()
        let boundedDuration = limits.duration.isFinite ? max(0, min(limits.duration, 60)) : 0
        let delta = UInt64(boundedDuration * 1_000_000_000)
        let addition = start.addingReportingOverflow(delta)
        var budget = ModelStoreTraversalBudget(
            limits: limits,
            deadline: addition.overflow ? UInt64.max : addition.partialValue,
            now: now,
            cancellationCheck: cancellationCheck
        )
        try validateDirectory(
            descriptor: descriptor,
            relativePrefix: "",
            depth: 0,
            budget: &budget
        )
        try budget.checkpoint()

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              sameDirectorySnapshot(before, after) else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        // Re-open the declared path after traversal so an ancestor/path swap
        // cannot make the returned string name a different directory.
        let rebound = try openNoFollowDirectory(at: canonical)
        defer { _ = Darwin.close(rebound) }
        var reboundMetadata = stat()
        guard Darwin.fstat(rebound, &reboundMetadata) == 0,
              sameDirectorySnapshot(after, reboundMetadata) else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        return (canonical, identity(after))
    }

    private static func validateDirectory(
        descriptor: Int32,
        relativePrefix: String,
        depth: Int,
        budget: inout ModelStoreTraversalBudget
    ) throws {
        try budget.checkpoint()
        let duplicate = Darwin.dup(descriptor)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 { _ = Darwin.close(duplicate) }
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        defer { _ = closedir(stream) }

        while true {
            try budget.checkpoint()
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw OllamaRuntimeSecurityError.unsafeModelStore }
                break
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            if name == "." || name == ".." { continue }
            guard !name.isEmpty, !name.contains("/"), !name.contains("\0") else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            let relative = relativePrefix.isEmpty ? name : "\(relativePrefix)/\(name)"
            try budget.consume(relativePath: relative, depth: depth + 1)

            var metadata = stat()
            let inspected = name.withCString {
                Darwin.fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }
            guard inspected == 0,
                  metadata.st_uid == geteuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            switch metadata.st_mode & S_IFMT {
            case S_IFREG:
                guard metadata.st_nlink == 1, metadata.st_size >= 0 else {
                    throw OllamaRuntimeSecurityError.unsafeModelStore
                }
            case S_IFDIR:
                let child = name.withCString {
                    Darwin.openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
                }
                guard child >= 0 else { throw OllamaRuntimeSecurityError.unsafeModelStore }
                do {
                    defer { _ = Darwin.close(child) }
                    var opened = stat()
                    guard Darwin.fstat(child, &opened) == 0,
                          sameObject(metadata, opened) else {
                        throw OllamaRuntimeSecurityError.unsafeModelStore
                    }
                    try validateDirectory(
                        descriptor: child,
                        relativePrefix: relative,
                        depth: depth + 1,
                        budget: &budget
                    )
                    var final = stat()
                    guard Darwin.fstat(child, &final) == 0,
                          sameDirectorySnapshot(opened, final) else {
                        throw OllamaRuntimeSecurityError.unsafeModelStore
                    }
                }
            default:
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
        }
    }

    private static func openNoFollowDirectory(at url: URL) throws -> Int32 {
        let components = try absolutePathComponents(of: url)
        var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw OllamaRuntimeSecurityError.unsafeModelStore }
        for component in components {
            var declared = stat()
            let inspected = component.withCString {
                Darwin.fstatat(descriptor, $0, &declared, AT_SYMLINK_NOFOLLOW)
            }
            let next = component.withCString {
                Darwin.openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
            }
            guard inspected == 0, next >= 0 else {
                if next >= 0 { _ = Darwin.close(next) }
                _ = Darwin.close(descriptor)
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            var opened = stat()
            let safeOwner = declared.st_uid == 0 || declared.st_uid == geteuid()
            let writableByOthers = declared.st_mode & (S_IWGRP | S_IWOTH) != 0
            let rootOwnedSticky = declared.st_uid == 0 && declared.st_mode & S_ISVTX != 0
            guard Darwin.fstat(next, &opened) == 0,
                  declared.st_mode & S_IFMT == S_IFDIR,
                  sameObject(declared, opened),
                  safeOwner,
                  !writableByOthers || rootOwnedSticky else {
                _ = Darwin.close(next)
                _ = Darwin.close(descriptor)
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            _ = Darwin.close(descriptor)
            descriptor = next
        }
        return descriptor
    }

    private static func absolutePathComponents(of url: URL) throws -> [String] {
        guard url.isFileURL else { throw OllamaRuntimeSecurityError.unsafeModelStore }
        let path = url.path
        guard path.hasPrefix("/"), !path.contains("\0"), path.utf8.count <= 4_096 else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        let pieces = path.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.first?.isEmpty == true, pieces.count > 1 else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        var components: [String] = []
        components.reserveCapacity(pieces.count - 1)
        for piece in pieces.dropFirst() {
            let component = String(piece)
            guard !component.isEmpty,
                  component != ".",
                  component != "..",
                  !component.contains("/") else {
                throw OllamaRuntimeSecurityError.unsafeModelStore
            }
            components.append(component)
        }
        guard "/" + components.joined(separator: "/") == path else {
            throw OllamaRuntimeSecurityError.unsafeModelStore
        }
        return components
    }

    private static func isSafeModelDirectory(_ metadata: stat) -> Bool {
        metadata.st_mode & S_IFMT == S_IFDIR
            && metadata.st_uid == geteuid()
            && metadata.st_mode & (S_IWGRP | S_IWOTH) == 0
    }

    private static func identity(_ metadata: stat) -> ModelStoreIdentity {
        ModelStoreIdentity(
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            permissions: UInt16(metadata.st_mode & 0o7777)
        )
    }

    private static func sameObject(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode
    }

    private static func sameDirectorySnapshot(_ lhs: stat, _ rhs: stat) -> Bool {
        sameObject(lhs, rhs)
            && lhs.st_uid == rhs.st_uid
            && lhs.st_size == rhs.st_size
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
            && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
            && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    static func makeProfile(runtimeRoot: URL, modelStore: URL) -> String {
        let readableRoots = [
            "/System", "/usr", "/bin", "/sbin", "/Library", "/Applications",
            "/private/etc", "/private/var/db", "/dev", runtimeRoot.path, modelStore.path
        ]
        let reads = readableRoots.map { "(subpath \(quote($0)))" }.joined(separator: " ")
        return [
            "(version 1)",
            "(allow default)",
            "(deny file-read*)",
            "(allow file-read-data (literal \(quote("/"))))",
            "(allow file-read* \(reads))",
            "(deny file-write*)",
            "(allow file-write* (literal \(quote("/dev/null"))) (subpath \(quote(runtimeRoot.path))))",
            "(deny network-outbound (require-not (remote ip \"localhost:*\")))",
            "(deny network-bind (require-not (local ip \"localhost:*\")))",
            "(deny appleevent-send)",
            "(deny mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd\") (global-name \"com.apple.securityd.xpc\") (global-name \"com.apple.securityd.general\"))"
        ].joined(separator: "\n")
    }

    private static func quote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
