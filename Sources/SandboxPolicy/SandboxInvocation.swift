import Darwin
import Foundation

public enum LocalHarnessSandboxMode: Equatable {
    case readOnly
    case workspaceWrite(URL)
    case supervisorChild
}

public enum LocalHarnessSandboxError: LocalizedError {
    case invalidArguments(String)
    case workspaceScanFailed(String)
    case workspaceScanLimitExceeded(LocalHarnessWorkspaceScanLimit)

    public var errorDescription: String? {
        switch self {
        case .invalidArguments(let detail): return "invalid runner arguments: \(detail)"
        case .workspaceScanFailed(let detail): return "workspace safety scan failed: \(detail)"
        case .workspaceScanLimitExceeded(let limit):
            return "workspace safety scan exceeded its \(limit.description)"
        }
    }
}

public enum LocalHarnessWorkspaceScanLimit: Equatable, Sendable {
    case entryCount(maximum: Int)
    case depth(maximum: Int)
    case nameBytes(maximum: Int)
    case pathBytes(maximum: Int)
    case aggregatePathBytes(maximum: Int)
    case deadline

    fileprivate var description: String {
        switch self {
        case .entryCount(let maximum): return "\(maximum)-entry limit"
        case .depth(let maximum): return "\(maximum)-level depth limit"
        case .nameBytes(let maximum): return "\(maximum)-byte filename limit"
        case .pathBytes(let maximum): return "\(maximum)-byte path limit"
        case .aggregatePathBytes(let maximum): return "\(maximum)-byte aggregate path limit"
        case .deadline: return "monotonic deadline"
        }
    }
}

struct LocalHarnessWorkspaceScanLimits: Equatable, Sendable {
    var maximumEntries: Int = 100_000
    var maximumDepth: Int = 64
    var maximumNameBytes: Int = Int(MAXNAMLEN)
    var maximumPathBytes: Int = 4_096
    var maximumAggregatePathBytes: Int = 32 * 1_024 * 1_024
    var maximumDurationNanoseconds: UInt64 = 2_000_000_000

    var isValid: Bool {
        (1...200_000).contains(maximumEntries) &&
            (1...128).contains(maximumDepth) &&
            (1...Int(MAXNAMLEN)).contains(maximumNameBytes) &&
            (1...(64 * 1_024)).contains(maximumPathBytes) &&
            maximumAggregatePathBytes >= maximumPathBytes &&
            maximumAggregatePathBytes <= 128 * 1_024 * 1_024 &&
            maximumDurationNanoseconds > 0 &&
            maximumDurationNanoseconds <= 60_000_000_000
    }
}

public struct LocalHarnessSandboxInvocation: Equatable {
    public let mode: LocalHarnessSandboxMode
    public let command: [String]
    public let profile: String
    public let approvedReadOnlyRoots: [URL]

    public init(
        arguments: [String],
        strictLocal: Bool,
        temporaryDirectory: URL? = nil,
        approvedWorkspaceRoots: [URL]? = nil,
        approvedReadOnlyRoots: [URL] = [],
        protectedUserHome: URL? = nil,
        currentDirectory: URL? = nil
    ) throws {
        let approvedRoots = approvedWorkspaceRoots?.map(Self.canonicalDirectory)
        let workingDirectory = Self.canonicalDirectory(
            currentDirectory ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        )
        let validatedReadOnlyRoots = try Self.validateReadOnlyRoots(approvedReadOnlyRoots)
        let validatedProtectedUserHome = try Self.validateProtectedUserHome(
            protectedUserHome ?? Self.systemAccountHomeDirectory()
        )
        let workspaceBoundaries = approvedRoots ?? [workingDirectory]
        for readOnlyRoot in validatedReadOnlyRoots {
            guard !workspaceBoundaries.contains(where: {
                Self.contains(parent: $0, child: readOnlyRoot) || Self.contains(parent: readOnlyRoot, child: $0)
            }) else {
                throw LocalHarnessSandboxError.invalidArguments("read-only roots must remain separate from workspace roots")
            }
        }
        self.approvedReadOnlyRoots = validatedReadOnlyRoots
        if arguments.starts(with: ["--supervisor-child", "--"]) {
            let parsedCommand = Array(arguments.dropFirst(2))
            guard let executable = parsedCommand.first, !executable.isEmpty else {
                throw LocalHarnessSandboxError.invalidArguments("missing supervisor child command")
            }
            guard let workspaceRoot = Self.approvedRoot(containing: workingDirectory, approvedRoots: approvedRoots) else {
                throw LocalHarnessSandboxError.invalidArguments("working directory is outside approved workspace roots")
            }
            mode = .supervisorChild
            command = parsedCommand
            profile = try Self.profile(
                mode: .supervisorChild,
                strictLocal: strictLocal,
                temporaryDirectory: temporaryDirectory,
                workspaceReadRoot: workspaceRoot,
                additionalReadOnlyRoots: validatedReadOnlyRoots,
                protectedUserHome: validatedProtectedUserHome,
                command: parsedCommand
            )
            return
        }

        var cursor = 0

        func value(_ expected: String) throws -> String {
            guard cursor < arguments.count else {
                throw LocalHarnessSandboxError.invalidArguments("expected \(expected)")
            }
            let result = arguments[cursor]
            cursor += 1
            return result
        }

        func expect(_ expected: String) throws {
            let actual = try value(expected)
            guard actual == expected else {
                throw LocalHarnessSandboxError.invalidArguments("expected \(expected), received \(actual)")
            }
        }

        try expect("--ro-bind")
        try expect("/")
        try expect("/")
        try expect("--dev")
        try expect("/dev")
        try expect("--unshare-pid")
        try expect("--proc")
        try expect("/proc")
        try expect("--die-with-parent")

        let parsedMode: LocalHarnessSandboxMode
        if cursor < arguments.count, arguments[cursor] == "--tmpfs" {
            try expect("--tmpfs")
            try expect("/tmp")
            try expect("--bind")
            let source = try value("workspace source")
            let destination = try value("workspace destination")
            guard source == destination, source.hasPrefix("/") else {
                throw LocalHarnessSandboxError.invalidArguments("workspace bind must use one absolute path")
            }
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: source, isDirectory: &isDirectory), isDirectory.boolValue else {
                throw LocalHarnessSandboxError.invalidArguments("workspace does not exist or is not a directory")
            }
            let workspace = Self.canonicalDirectory(URL(fileURLWithPath: source, isDirectory: true))
            guard Self.approvedRoot(containing: workspace, approvedRoots: approvedRoots) != nil else {
                throw LocalHarnessSandboxError.invalidArguments("workspace is outside approved workspace roots")
            }
            parsedMode = .workspaceWrite(workspace)
        } else {
            parsedMode = .readOnly
        }

        try expect("--")
        let parsedCommand = Array(arguments.dropFirst(cursor))
        guard let executable = parsedCommand.first, !executable.isEmpty else {
            throw LocalHarnessSandboxError.invalidArguments("missing command")
        }

        mode = parsedMode
        command = parsedCommand
        let workspaceReadRoot: URL?
        switch parsedMode {
        case .workspaceWrite(let workspace): workspaceReadRoot = workspace
        case .readOnly: workspaceReadRoot = Self.approvedRoot(containing: workingDirectory, approvedRoots: approvedRoots)
        case .supervisorChild: workspaceReadRoot = nil
        }
        guard workspaceReadRoot != nil else {
            throw LocalHarnessSandboxError.invalidArguments("working directory is outside approved workspace roots")
        }
        profile = try Self.profile(
            mode: parsedMode,
            strictLocal: strictLocal,
            temporaryDirectory: temporaryDirectory,
            workspaceReadRoot: workspaceReadRoot,
            additionalReadOnlyRoots: validatedReadOnlyRoots,
            protectedUserHome: validatedProtectedUserHome,
            command: parsedCommand
        )
    }

    private static func profile(
        mode: LocalHarnessSandboxMode,
        strictLocal: Bool,
        temporaryDirectory: URL?,
        workspaceReadRoot: URL?,
        additionalReadOnlyRoots: [URL],
        protectedUserHome: URL,
        command: [String]
    ) throws -> String {
        var forms = ["(version 1)", "(allow default)"]

        // Upstream DSH confines writes but deliberately allows every read. Local
        // Harness is a private-data application, so model-controlled processes
        // receive a read allowlist as well: the selected workspace, the private
        // per-app temp root, and immutable operating-system/toolchain locations.
        forms.append("(deny file-read*)")
        // dyld on current macOS opens the root directory while locating the
        // shared cache. Directory-data access to this one literal reveals only
        // the top-level names; descendants remain governed by the allowlist.
        forms.append("(allow file-read-data (literal \(quote("/"))))")
        let systemSelectorReadRoots = try validatedSystemSelectorReadRoots()
        var readableRoots = [
            "/System", "/usr", "/bin", "/sbin", "/Library", "/Applications", "/opt/homebrew",
            "/private/etc", "/private/var/db", "/dev"
        ]
        readableRoots.append(contentsOf: systemSelectorReadRoots)
        if let workspaceReadRoot { readableRoots.append(contentsOf: policyPaths(workspaceReadRoot)) }
        readableRoots.append(contentsOf: additionalReadOnlyRoots.flatMap(policyPaths))
        let privateTemp = canonicalDirectory(temporaryDirectory ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true))
        readableRoots.append(contentsOf: policyPaths(privateTemp))
        if let executable = command.first, executable.hasPrefix("/") {
            readableRoots.append(contentsOf: policyPaths(URL(fileURLWithPath: executable).deletingLastPathComponent()))
        }
        let readableRules = Array(Set(readableRoots)).sorted()
            .map { "(subpath \(quote($0)))" }.joined(separator: " ")
        forms.append("(allow file-read* \(readableRules))")
        if !systemSelectorReadRoots.isEmpty {
            // Seatbelt may evaluate the selector vnode itself separately from
            // its resolved target. Name both validated selector vnodes
            // literally in addition to the narrow subtree rule above.
            forms.append(#"(allow file-read* (literal "/private/var/select") (literal "/private/var/select/sh"))"#)
        }
        let traversalRules = Array(Set(readableRoots.flatMap(parentDirectories))).sorted()
            .map { "(literal \(quote($0)))" }.joined(separator: " ")
        if !traversalRules.isEmpty {
            forms.append("(allow file-read-metadata \(traversalRules))")
        }

        forms.append("(deny file-write*)")
        forms.append("(allow file-write* (literal \(quote("/dev/null"))))")

        let writableWorkspace: URL?
        switch mode {
        case .workspaceWrite(let workspace): writableWorkspace = workspace
        case .supervisorChild: writableWorkspace = workspaceReadRoot
        case .readOnly: writableWorkspace = nil
        }
        if let workspace = writableWorkspace {
            let roots = Array(Set(policyPaths(workspace) + policyPaths(privateTemp))).sorted()
            let writableRoots = roots.map { "(subpath \(quote($0)))" }.joined(separator: " ")
            forms.append("(allow file-write* \(writableRoots))")
            let hardLinkedFiles = try hardLinkedRegularFiles(in: workspace)
            if !hardLinkedFiles.isEmpty {
                let protectedAliases = hardLinkedFiles.map { "(literal \(quote($0)))" }.joined(separator: " ")
                forms.append("(deny file-write* \(protectedAliases))")
            }
        }
        if !additionalReadOnlyRoots.isEmpty {
            let immutableRoots = additionalReadOnlyRoots
                .flatMap(policyPaths)
                .map { "(subpath \(quote($0)))" }
                .joined(separator: " ")
            forms.append("(deny file-write* \(immutableRoots))")
        }

        // Model tools and descendants never receive direct access to private stores,
        // Keychain IPC, Apple Events, or the app's privileged helpers. These controls
        // remain in force in Connected mode; that mode changes network egress only.
        forms.append(#"""
            (deny process-exec
              (regex #"/LocalHarness(Credential|Update|Scheduler)Helper$")
              (regex #"/LocalHarness(RuntimeLease|SandboxRunner)$")
              (regex #"/Fulmar\.app/Contents/MacOS/LocalHarness(Credential|Update|Scheduler)Helper$")
              (regex #"/Fulmar\.app/Contents/MacOS/LocalHarness(RuntimeLease|SandboxRunner)$"))
            (deny mach-lookup
              (global-name "com.apple.SecurityServer")
              (global-name "com.apple.securityd")
              (global-name "com.apple.securityd.xpc")
              (global-name "com.apple.securityd.general"))
            (deny appleevent-send)
            (deny file-read-data file-write*
              (regex #"^/Users/[^/]+/Library/Keychains(/|$)")
              (regex #"^/Users/[^/]+/Library/Mail(/|$)")
              (regex #"^/Users/[^/]+/Library/Messages(/|$)")
              (regex #"^/Users/[^/]+/Library/Safari(/|$)")
              (regex #"^/Users/[^/]+/Library/Application Support/(Google/Chrome|Firefox|BraveSoftware|1Password|Arc|Microsoft Edge)(/|$)")
              (regex #"^/Users/[^/]+/\.(aws|azure)(/|$)")
              (regex #"^/Users/[^/]+/\.(docker|gnupg|kube)(/|$)")
              (regex #"^/Users/[^/]+/\.config/(gcloud|gh)(/|$)")
              (regex #"^/Users/[^/]+/\.(netrc|git-credentials|npmrc|pypirc)$")
              (regex #"^/Users/[^/]+/\.ssh(/|$)"))
            """#)
        // `/Users/<name>` is the conventional macOS layout, but mobile and
        // external accounts may have a different securely provisioned login
        // home. Retain the broad conventional denials above and add exact
        // literal/subpath denials derived from the canonical, owner-safe POSIX
        // account home. This expands defense in depth without granting a read
        // or write capability and without trusting HOME from the child env.
        let protectedHomePaths = policyPaths(protectedUserHome)
        let sensitiveSubpaths = [
            "Library/Keychains", "Library/Mail", "Library/Messages", "Library/Safari",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Firefox",
            "Library/Application Support/BraveSoftware",
            "Library/Application Support/1Password",
            "Library/Application Support/Arc",
            "Library/Application Support/Microsoft Edge",
            ".aws", ".azure", ".docker", ".gnupg", ".kube",
            ".config/gcloud", ".config/gh", ".ssh"
        ]
        let sensitiveFiles = [".netrc", ".git-credentials", ".npmrc", ".pypirc"]
        let protectedHomeRules = protectedHomePaths.flatMap { home in
            sensitiveSubpaths.map { "(subpath \(quote(home + "/" + $0)))" }
                + sensitiveFiles.map { "(literal \(quote(home + "/" + $0)))" }
        }.joined(separator: " ")
        forms.append("(deny file-read-data file-write* \(protectedHomeRules))")
        // Keep ordinary fork/exec available for coding tools, but block direct
        // attempts to detach from the runner-owned process group. macOS does
        // not expose an entitlement-free job object, so the lifecycle monitor
        // remains authoritative for the group and this is defense in depth.
        forms.append("(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid))")
        // Tool processes never receive direct egress, including to arbitrary
        // services listening elsewhere on this Mac. Provider traffic belongs
        // exclusively to the guarded in-process transport, which can enforce
        // one exact app-owned Ollama origin or one consented external origin.
        forms.append("(deny network-outbound)")
        return forms.joined(separator: "\n")
    }

    private static func canonicalDirectory(_ url: URL) -> URL {
        url.resolvingSymlinksInPath().standardizedFileURL
    }

    private static func systemAccountHomeDirectory() throws -> URL {
        let configured = Darwin.sysconf(_SC_GETPW_R_SIZE_MAX)
        let capacity = configured > 0 && configured <= 1_048_576
            ? Int(configured)
            : 16_384
        var record = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: capacity)
        let status = buffer.withUnsafeMutableBufferPointer { storage in
            Darwin.getpwuid_r(
                Darwin.geteuid(),
                &record,
                storage.baseAddress,
                storage.count,
                &result
            )
        }
        guard status == 0, result != nil, let pointer = record.pw_dir else {
            throw LocalHarnessSandboxError.invalidArguments(
                "could not resolve the protected user home"
            )
        }
        return URL(fileURLWithPath: String(cString: pointer), isDirectory: true)
    }

    private static func validateProtectedUserHome(_ supplied: URL) throws -> URL {
        let home = supplied
        let path = home.path
        let components = path.components(separatedBy: "/")
        guard home.isFileURL,
              path.hasPrefix("/"), path != "/", !path.hasSuffix("/"),
              path.utf8.count <= 4_096,
              components.first == "",
              components.dropFirst().allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".."
              }),
              path.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }),
              let resolved = path.withCString({ Darwin.realpath($0, nil) }) else {
            throw LocalHarnessSandboxError.invalidArguments(
                "protected user home is not a canonical absolute directory"
            )
        }
        defer { Darwin.free(resolved) }
        guard String(cString: resolved) == path else {
            throw LocalHarnessSandboxError.invalidArguments(
                "protected user home cannot traverse a symbolic link"
            )
        }

        let requiresACLFreeAncestry = !isConventionalUsersHome(path)
        var cursor = ""
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            cursor += "/" + component
            var metadata = stat()
            guard Darwin.lstat(cursor, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0 || metadata.st_uid == Darwin.geteuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
                  !requiresACLFreeAncestry
                    || directoryHasNoExtendedACL(at: cursor, matching: metadata) else {
                throw LocalHarnessSandboxError.invalidArguments(
                    "protected user home has unsafe ancestry"
                )
            }
        }
        var homeMetadata = stat()
        guard Darwin.lstat(path, &homeMetadata) == 0,
              homeMetadata.st_uid == Darwin.geteuid() else {
            throw LocalHarnessSandboxError.invalidArguments(
                "protected user home is not owned by the current account"
            )
        }
        return home
    }

    private static func isConventionalUsersHome(_ path: String) -> Bool {
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        return components.count == 2 && components.first == "Users"
    }

    private static func directoryHasNoExtendedACL(
        at path: String,
        matching metadata: stat
    ) -> Bool {
        let descriptor = Darwin.open(
            path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard descriptor >= 0 else { return false }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_dev == metadata.st_dev,
              opened.st_ino == metadata.st_ino else {
            return false
        }
        errno = 0
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT
        }
        _ = acl_free(UnsafeMutableRawPointer(accessControlList))
        return false
    }

    /// Foundation presents the Darwin `/private/tmp` and `/private/var`
    /// aliases as `/tmp` and `/var` on current macOS releases, while Seatbelt
    /// can receive the kernel-canonical `/private/...` spelling at exec time.
    /// Admit both names for the same already-approved vnode; this does not add
    /// a new directory or widen the read/write capability.
    private static func policyPaths(_ url: URL) -> [String] {
        let foundationPath = canonicalDirectory(url).path
        var paths = Set([foundationPath])
        for candidate in [url.path, foundationPath] {
            guard let resolved = candidate.withCString({ Darwin.realpath($0, nil) }) else { continue }
            paths.insert(String(cString: resolved))
            free(resolved)
        }
        return paths.sorted()
    }

    private static func parentDirectories(of path: String) -> [String] {
        var result: [String] = []
        var cursor = path
        while cursor != "/", let separator = cursor.lastIndex(of: "/") {
            cursor = separator == cursor.startIndex ? "/" : String(cursor[..<separator])
            result.append(cursor)
        }
        return result
    }

    /// Current macOS releases let `/bin/sh` consult the system-owned selector
    /// at `/private/var/select/sh`. Admit that one tiny system subtree only
    /// after proving its complete ancestry is root-owned and not writable by
    /// non-root users, the selector is the exact expected root-owned symlink,
    /// and its target is the immutable system bash binary. A missing selector
    /// is valid on older supported macOS releases; an unsafe existing selector
    /// fails the sandbox closed.
    private static func validatedSystemSelectorReadRoots() throws -> [String] {
        let selectorRoot = "/private/var/select"
        var rootMetadata = stat()
        guard Darwin.lstat(selectorRoot, &rootMetadata) == 0 else {
            if errno == ENOENT { return [] }
            throw LocalHarnessSandboxError.invalidArguments("could not validate the system shell selector")
        }

        for directory in ["/private", "/private/var", selectorRoot] {
            var metadata = stat()
            guard Darwin.lstat(directory, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0,
                  metadata.st_mode & 0o022 == 0 else {
                throw LocalHarnessSandboxError.invalidArguments("the system shell selector has unsafe ancestry")
            }
        }

        let selector = "\(selectorRoot)/sh"
        var selectorMetadata = stat()
        guard Darwin.lstat(selector, &selectorMetadata) == 0,
              selectorMetadata.st_mode & S_IFMT == S_IFLNK,
              selectorMetadata.st_uid == 0 else {
            throw LocalHarnessSandboxError.invalidArguments("the system shell selector is missing or unsafe")
        }
        var targetBytes = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let targetCount = targetBytes.withUnsafeMutableBytes { bytes in
            Darwin.readlink(selector, bytes.baseAddress, bytes.count)
        }
        guard targetCount > 0,
              String(decoding: targetBytes.prefix(targetCount), as: UTF8.self) == "/bin/bash" else {
            throw LocalHarnessSandboxError.invalidArguments("the system shell selector target is unexpected")
        }

        var targetMetadata = stat()
        guard Darwin.lstat("/bin/bash", &targetMetadata) == 0,
              targetMetadata.st_mode & S_IFMT == S_IFREG,
              targetMetadata.st_uid == 0,
              targetMetadata.st_mode & 0o022 == 0 else {
            throw LocalHarnessSandboxError.invalidArguments("the selected system shell is unsafe")
        }
        return [selectorRoot]
    }

    private static func validateReadOnlyRoots(_ candidates: [URL]) throws -> [URL] {
        guard candidates.count <= 8 else {
            throw LocalHarnessSandboxError.invalidArguments("too many read-only roots")
        }
        var seen = Set<String>()
        var result: [URL] = []
        for candidate in candidates {
            guard candidate.isFileURL, candidate.path.hasPrefix("/"), !candidate.path.contains("\0") else {
                throw LocalHarnessSandboxError.invalidArguments("read-only root is not an absolute local path")
            }
            var configuredMetadata = stat()
            guard Darwin.lstat(candidate.path, &configuredMetadata) == 0,
                  configuredMetadata.st_mode & S_IFMT == S_IFDIR else {
                throw LocalHarnessSandboxError.invalidArguments("read-only root is missing, linked, or not a directory")
            }
            let canonical = canonicalDirectory(candidate)
            var canonicalMetadata = stat()
            guard canonical.path != "/",
                  Darwin.lstat(canonical.path, &canonicalMetadata) == 0,
                  canonicalMetadata.st_mode & S_IFMT == S_IFDIR,
                  canonicalMetadata.st_uid == geteuid(),
                  canonicalMetadata.st_mode & 0o077 == 0 else {
                throw LocalHarnessSandboxError.invalidArguments("read-only root must be an owner-only app directory")
            }
            if seen.insert(canonical.path).inserted { result.append(canonical) }
        }
        return result.sorted { $0.path < $1.path }
    }

    private static func approvedRoot(containing candidate: URL, approvedRoots: [URL]?) -> URL? {
        // `nil` is retained only as a source-compatibility convenience for
        // embedders/tests. The production runner always supplies an explicit,
        // non-empty list and refuses to start when it is absent.
        guard let approvedRoots else { return candidate }
        return approvedRoots
            .filter { contains(parent: $0, child: candidate) }
            .max { $0.path.count < $1.path.count }
    }

    private static func contains(parent: URL, child: URL) -> Bool {
        let root = canonicalDirectory(parent).path
        let target = canonicalDirectory(child).path
        return target == root || target.hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }

    /// Streams the mutable workspace through descriptor-relative, no-follow
    /// operations. Every raw directory entry consumes the global budget before
    /// its metadata is inspected, so a wide or hostile tree cannot be retained
    /// by Foundation's whole-tree enumerator. The scan deliberately has no
    /// cache: a cached link count would be stale at the next tool launch.
    static func hardLinkedRegularFiles(
        in workspace: URL,
        limits: LocalHarnessWorkspaceScanLimits = .init(),
        monotonicNow: () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) throws -> [String] {
        guard limits.isValid else {
            throw LocalHarnessSandboxError.workspaceScanFailed("scan limits are invalid")
        }
        let workspacePath = workspace.standardizedFileURL.path
        guard workspace.isFileURL,
              workspacePath.hasPrefix("/"),
              !workspacePath.contains("\0"),
              workspacePath.utf8.count <= limits.maximumPathBytes else {
            throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                .pathBytes(maximum: limits.maximumPathBytes)
            )
        }

        let started = monotonicNow()
        func checkDeadline() throws {
            let current = monotonicNow()
            guard current >= started,
                  current - started <= limits.maximumDurationNanoseconds else {
                throw LocalHarnessSandboxError.workspaceScanLimitExceeded(.deadline)
            }
        }
        try checkDeadline()

        var pathMetadata = stat()
        guard Darwin.lstat(workspacePath, &pathMetadata) == 0,
              pathMetadata.st_mode & S_IFMT == S_IFDIR else {
            throw LocalHarnessSandboxError.workspaceScanFailed("workspace root is missing, linked, or not a directory")
        }
        let rootDescriptor = Darwin.open(
            workspacePath,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard rootDescriptor >= 0 else {
            throw LocalHarnessSandboxError.workspaceScanFailed("could not open workspace root")
        }
        defer { Darwin.close(rootDescriptor) }
        var openedRoot = stat()
        guard Darwin.fstat(rootDescriptor, &openedRoot) == 0,
              openedRoot.st_mode & S_IFMT == S_IFDIR,
              sameNode(pathMetadata, openedRoot) else {
            throw LocalHarnessSandboxError.workspaceScanFailed("workspace root changed while opening")
        }

        var encounteredEntries = 0
        var aggregatePathBytes = 0
        var aliases: [String] = []

        func visit(
            directoryDescriptor: Int32,
            relativeComponents: [String]
        ) throws {
            try checkDeadline()
            var directoryBefore = stat()
            guard Darwin.fstat(directoryDescriptor, &directoryBefore) == 0,
                  directoryBefore.st_mode & S_IFMT == S_IFDIR else {
                throw LocalHarnessSandboxError.workspaceScanFailed("workspace directory became unavailable")
            }

            let iterationDescriptor = Darwin.dup(directoryDescriptor)
            guard iterationDescriptor >= 0 else {
                throw LocalHarnessSandboxError.workspaceScanFailed("could not duplicate workspace directory")
            }
            guard let stream = fdopendir(iterationDescriptor) else {
                Darwin.close(iterationDescriptor)
                throw LocalHarnessSandboxError.workspaceScanFailed("could not enumerate workspace directory")
            }
            defer { closedir(stream) }

            while true {
                try checkDeadline()
                errno = 0
                guard let entry = readdir(stream) else {
                    if errno != 0 {
                        throw LocalHarnessSandboxError.workspaceScanFailed("workspace directory enumeration failed")
                    }
                    break
                }
                guard let (name, nameByteCount) = directoryEntryName(entry) else {
                    throw LocalHarnessSandboxError.workspaceScanFailed("workspace contains an invalid filename")
                }
                if name == "." || name == ".." { continue }

                encounteredEntries += 1
                guard encounteredEntries <= limits.maximumEntries else {
                    throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                        .entryCount(maximum: limits.maximumEntries)
                    )
                }
                guard nameByteCount <= limits.maximumNameBytes else {
                    throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                        .nameBytes(maximum: limits.maximumNameBytes)
                    )
                }
                let components = relativeComponents + [name]
                guard components.count <= limits.maximumDepth else {
                    throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                        .depth(maximum: limits.maximumDepth)
                    )
                }
                let relativePath = components.joined(separator: "/")
                let absolutePath = workspacePath.hasSuffix("/")
                    ? workspacePath + relativePath
                    : workspacePath + "/" + relativePath
                let pathByteCount = absolutePath.utf8.count
                guard pathByteCount <= limits.maximumPathBytes else {
                    throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                        .pathBytes(maximum: limits.maximumPathBytes)
                    )
                }
                let (nextAggregate, aggregateOverflow) = aggregatePathBytes.addingReportingOverflow(pathByteCount)
                guard !aggregateOverflow,
                      nextAggregate <= limits.maximumAggregatePathBytes else {
                    throw LocalHarnessSandboxError.workspaceScanLimitExceeded(
                        .aggregatePathBytes(maximum: limits.maximumAggregatePathBytes)
                    )
                }
                aggregatePathBytes = nextAggregate

                try checkDeadline()
                var entryMetadata = stat()
                guard Darwin.fstatat(
                    directoryDescriptor,
                    name,
                    &entryMetadata,
                    AT_SYMLINK_NOFOLLOW
                ) == 0 else {
                    throw LocalHarnessSandboxError.workspaceScanFailed(
                        "workspace changed during safety scan"
                    )
                }
                switch entryMetadata.st_mode & S_IFMT {
                case S_IFREG:
                    if entryMetadata.st_nlink > 1 { aliases.append(absolutePath) }
                case S_IFDIR:
                    let childDescriptor = Darwin.openat(
                        directoryDescriptor,
                        name,
                        O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
                    )
                    guard childDescriptor >= 0 else {
                        throw LocalHarnessSandboxError.workspaceScanFailed(
                            "workspace directory changed during safety scan"
                        )
                    }
                    do {
                        defer { Darwin.close(childDescriptor) }
                        var openedChild = stat()
                        guard Darwin.fstat(childDescriptor, &openedChild) == 0,
                              openedChild.st_mode & S_IFMT == S_IFDIR,
                              sameNode(entryMetadata, openedChild) else {
                            throw LocalHarnessSandboxError.workspaceScanFailed(
                                "workspace directory changed while opening"
                            )
                        }
                        try visit(
                            directoryDescriptor: childDescriptor,
                            relativeComponents: components
                        )
                        var childAfterPath = stat()
                        guard Darwin.fstatat(
                            directoryDescriptor,
                            name,
                            &childAfterPath,
                            AT_SYMLINK_NOFOLLOW
                        ) == 0,
                              childAfterPath.st_mode & S_IFMT == S_IFDIR,
                              sameNode(openedChild, childAfterPath) else {
                            throw LocalHarnessSandboxError.workspaceScanFailed(
                                "workspace directory changed after traversal"
                            )
                        }
                    }
                default:
                    // Symbolic links and special nodes are not followed and do
                    // not expose a writable regular-file hard-link alias.
                    continue
                }
            }

            try checkDeadline()
            var directoryAfter = stat()
            guard Darwin.fstat(directoryDescriptor, &directoryAfter) == 0,
                  stableDirectorySnapshot(directoryBefore, directoryAfter) else {
                throw LocalHarnessSandboxError.workspaceScanFailed(
                    "workspace changed during directory traversal"
                )
            }
        }

        try visit(directoryDescriptor: rootDescriptor, relativeComponents: [])
        try checkDeadline()
        var finalPathMetadata = stat()
        var finalDescriptorMetadata = stat()
        guard Darwin.lstat(workspacePath, &finalPathMetadata) == 0,
              Darwin.fstat(rootDescriptor, &finalDescriptorMetadata) == 0,
              finalPathMetadata.st_mode & S_IFMT == S_IFDIR,
              stableDirectorySnapshot(openedRoot, finalDescriptorMetadata),
              sameNode(openedRoot, finalPathMetadata) else {
            throw LocalHarnessSandboxError.workspaceScanFailed(
                "workspace root changed during safety scan"
            )
        }
        return aliases.sorted()
    }

    private static func directoryEntryName(
        _ entry: UnsafeMutablePointer<dirent>
    ) -> (String, Int)? {
        let count = Int(entry.pointee.d_namlen)
        let recordByteCount = Int(entry.pointee.d_reclen)
        guard let nameOffset = MemoryLayout<dirent>.offset(of: \dirent.d_name),
              count > 0,
              count <= Int(MAXNAMLEN),
              recordByteCount <= MemoryLayout<dirent>.size,
              nameOffset <= recordByteCount,
              count < recordByteCount - nameOffset else { return nil }
        let bytes = UnsafeRawBufferPointer(
            start: UnsafeRawPointer(entry).advanced(by: nameOffset),
            count: count + 1
        )
        let nameBytes = bytes.prefix(count)
        guard bytes[count] == 0,
              !nameBytes.contains(0),
              !nameBytes.contains(47),
              let name = String(bytes: nameBytes, encoding: .utf8) else {
            return nil
        }
        return (name, count)
    }

    private static func sameNode(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
    }

    private static func stableDirectorySnapshot(_ lhs: stat, _ rhs: stat) -> Bool {
        sameNode(lhs, rhs) &&
            lhs.st_mode & S_IFMT == S_IFDIR &&
            rhs.st_mode & S_IFMT == S_IFDIR &&
            lhs.st_nlink == rhs.st_nlink &&
            lhs.st_size == rhs.st_size &&
            lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec &&
            lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec &&
            lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec &&
            lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func quote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
