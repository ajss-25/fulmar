import Darwin
import Foundation

enum HarnessRuntimeWriteSandboxError: LocalizedError, Equatable {
    case unavailable
    case unsafeRoot
    case invalidLaunch

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "macOS could not establish Fulmar's Harness write boundary. Provider work remained blocked."
        case .unsafeRoot:
            return "Fulmar's Harness write boundary contains a linked, permissive, or changed storage root. Provider work remained blocked."
        case .invalidLaunch:
            return "Fulmar refused an invalid Harness sandbox launch. Provider work remained blocked."
        }
    }
}

/// A process-wide Seatbelt boundary around the DSH host itself. Model-facing
/// tools retain their narrower per-call sandbox, while this outer profile
/// prevents a compromised runtime or plugin from changing native trust,
/// recovery, backup, migration, or ownership records.
struct HarnessRuntimeWriteSandbox: Equatable {
    static let executable = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
    static let maximumProfileBytes = 64 * 1_024

    let profile: String
    private let executableIdentity: HarnessRuntimeSandboxExecutableIdentity
    private let rootIdentities: [HarnessRuntimeSandboxDirectoryIdentity]

    static func prepare(
        applicationSupport: URL,
        harnessHome: URL,
        workspace: URL,
        telemetryDirectory: URL?
    ) throws -> HarnessRuntimeWriteSandbox {
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw HarnessRuntimeWriteSandboxError.unavailable
        }
        let support = try secureCanonicalDirectory(applicationSupport)
        let home = try secureCanonicalDirectory(harnessHome)
        let work = try secureCanonicalDirectory(workspace)
        guard strictlyContains(support, home),
              strictlyContains(support, work),
              !contains(home, work),
              !contains(work, home) else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        let telemetry: URL?
        if let telemetryDirectory {
            let value = try secureCanonicalDirectory(telemetryDirectory)
            guard strictlyContains(support, value),
                  !contains(home, value),
                  !contains(value, home),
                  !contains(work, value),
                  !contains(value, work) else {
                throw HarnessRuntimeWriteSandboxError.unsafeRoot
            }
            telemetry = value
        } else {
            telemetry = nil
        }

        var writable = [home, work]
        if let telemetry { writable.append(telemetry) }
        let writableRules = writable
            .flatMap(policyPaths)
            .map { "(subpath \(quote($0)))" }
            .sorted()
            .joined(separator: " ")

        let protected = [
            support.appendingPathComponent(".FulmarControl", isDirectory: true),
            support.appendingPathComponent("DeviceTrustRecovery", isDirectory: true),
            support.appendingPathComponent(".provider-history-auxiliary-transaction", isDirectory: true),
            support.appendingPathComponent("ProviderHistoryAuxiliaryRecovery", isDirectory: true),
            support.appendingPathComponent("HarnessHomeRecovery", isDirectory: true),
            support.appendingPathComponent("Backups", isDirectory: true),
            support.appendingPathComponent(".local-harness-state-recovery", isDirectory: true),
            support.appendingPathComponent("Migration", isDirectory: true),
            // Active skill packages are native-reviewed executable input. A
            // model-facing plugin may read them, but it must never persist a
            // replacement for the next launch.
            home.appendingPathComponent("skills", isDirectory: true),
            // Node resolves packages through ancestor `node_modules` roots.
            // Protect every profile-resolution location, not just the reviewed
            // manifest, so a compromised runtime cannot persist an undeclared
            // shadow package for the next launch. Fulmar's signed runtime and
            // plugins live in the read-only application bundle instead.
            home.appendingPathComponent("node_modules", isDirectory: true),
            home.appendingPathComponent("profiles/node_modules", isDirectory: true),
            home.appendingPathComponent("profiles/web/node_modules", isDirectory: true)
        ]
        let protectedSubpaths = protected
            .flatMap(policyPaths)
            .map { "(subpath \(quote($0)))" }
            .sorted()
            .joined(separator: " ")
        let protectedFiles = [
            home.appendingPathComponent(
                ProviderHistoryPrivacyEpoch.ownershipReceiptName,
                isDirectory: false
            ),
            home.appendingPathComponent(
                WorkspaceMutationPolicyStore.fileName,
                isDirectory: false
            ),
            home.appendingPathComponent(".credentials.yaml", isDirectory: false),
            home.appendingPathComponent(".credentials.yml", isDirectory: false),
            home.appendingPathComponent(".env", isDirectory: false),
            home.appendingPathComponent("cordis.patch.yml", isDirectory: false),
            home.appendingPathComponent("AGENTS.md", isDirectory: false),
            home.appendingPathComponent("profiles/.env", isDirectory: false),
            home.appendingPathComponent("profiles/web/.env", isDirectory: false),
            home.appendingPathComponent("profiles/web/package.json", isDirectory: false),
            home.appendingPathComponent("profiles/web/cordis.patch.yml", isDirectory: false)
        ]
        let protectedLiterals = protectedFiles.flatMap(policyPaths)
            .map { "(literal \(quote($0)))" }
            .sorted()
            .joined(separator: " ")

        let profile = [
            "(version 1)",
            "(allow default)",
            "(deny file-write*)",
            "(allow file-write* (literal \(quote("/dev/null"))) \(writableRules))",
            "(deny file-write* \(protectedSubpaths) \(protectedLiterals))"
        ].joined(separator: "\n")
        guard !profile.contains("\0"), profile.utf8.count <= maximumProfileBytes else {
            throw HarnessRuntimeWriteSandboxError.invalidLaunch
        }
        return HarnessRuntimeWriteSandbox(
            profile: profile,
            executableIdentity: try HarnessRuntimeSandboxExecutableIdentity.capture(executable),
            rootIdentities: try ([support, home, work] + (telemetry.map { [$0] } ?? []))
                .map(HarnessRuntimeSandboxDirectoryIdentity.capture)
        )
    }

    func wrappedLaunch(
        executable target: URL,
        arguments: [String]
    ) throws -> (executable: URL, arguments: [String]) {
        guard target.isFileURL,
              target.path.hasPrefix("/"),
              !target.path.contains("\0"),
              target.standardizedFileURL.path == target.path,
              arguments.count <= 4_096,
              arguments.allSatisfy({ !$0.contains("\0") && $0.utf8.count <= 64 * 1_024 }) else {
            throw HarnessRuntimeWriteSandboxError.invalidLaunch
        }
        try executableIdentity.revalidate()
        for identity in rootIdentities { try identity.revalidate() }
        return (Self.executable, ["-p", profile, target.path] + arguments)
    }

    private static func secureCanonicalDirectory(_ url: URL) throws -> URL {
        guard url.isFileURL,
              url.path.hasPrefix("/"),
              profilePathIsSafe(url.path) else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == Darwin.geteuid(),
              metadata.st_mode & 0o077 == 0 else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessRuntimeWriteSandboxError.unsafeRoot }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_dev == metadata.st_dev,
              opened.st_ino == metadata.st_ino,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor),
              let canonical = canonicalExistingPath(url),
              pathMatchesCanonicalSpelling(url.path, canonical: canonical) else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        return url
    }

    /// `realpath(3)` reports `/private/tmp` and `/private/var` as canonical,
    /// while callers and Foundation commonly hold the aliased `/tmp` and
    /// `/var` spellings; Foundation's own standardization strips `/private`,
    /// so requiring exact equality would make every root under those system
    /// aliases unsatisfiable. Accept exactly the caller spelling itself or
    /// the one documented macOS alias whose only difference is the
    /// `/private` prefix. Any other symlink component changes more than the
    /// prefix and is rejected; `policyPaths` continues to emit both
    /// spellings into the Seatbelt profile.
    private static func pathMatchesCanonicalSpelling(
        _ path: String,
        canonical: String
    ) -> Bool {
        if canonical == path { return true }
        guard canonical == "/private" + path else { return false }
        return path == "/tmp" || path.hasPrefix("/tmp/")
            || path == "/var" || path.hasPrefix("/var/")
            || path == "/etc" || path.hasPrefix("/etc/")
    }

    private static func canonicalExistingPath(_ url: URL) -> String? {
        var bytes = [CChar](repeating: 0, count: Int(PATH_MAX))
        return bytes.withUnsafeMutableBufferPointer { destination in
            url.path.withCString { source in
                guard let base = destination.baseAddress,
                      Darwin.realpath(source, base) != nil else { return nil }
                return String(cString: base)
            }
        }
    }

    private static func contains(_ root: URL, _ child: URL) -> Bool {
        child.path == root.path || child.path.hasPrefix(root.path + "/")
    }

    private static func strictlyContains(_ root: URL, _ child: URL) -> Bool {
        root != child && child.path.hasPrefix(root.path + "/")
    }

    private static func policyPaths(_ url: URL) -> [String] {
        var values = Set([url.standardizedFileURL.path])
        if let canonical = canonicalExistingPath(url) { values.insert(canonical) }
        let value = url.standardizedFileURL.path
        if value.hasPrefix("/var/") || value == "/var" { values.insert("/private" + value) }
        if value.hasPrefix("/tmp/") || value == "/tmp" { values.insert("/private" + value) }
        return values.sorted()
    }

    private static func quote(_ value: String) -> String {
        "\"" + value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    private static func profilePathIsSafe(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy {
            $0.value >= 0x20 && $0.value != 0x7f
        }
    }
}

private struct HarnessRuntimeSandboxDirectoryIdentity: Equatable {
    let url: URL
    let device: UInt64
    let inode: UInt64
    let owner: UInt32
    let permissions: UInt16

    static func capture(_ url: URL) throws -> HarnessRuntimeSandboxDirectoryIdentity {
        var pathMetadata = stat()
        guard Darwin.lstat(url.path, &pathMetadata) == 0,
              pathMetadata.st_mode & S_IFMT == S_IFDIR,
              pathMetadata.st_uid == Darwin.geteuid(),
              pathMetadata.st_mode & 0o077 == 0 else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        let descriptor = Darwin.open(
            url.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else { throw HarnessRuntimeWriteSandboxError.unsafeRoot }
        defer { _ = Darwin.close(descriptor) }
        var opened = stat()
        guard Darwin.fstat(descriptor, &opened) == 0,
              opened.st_dev == pathMetadata.st_dev,
              opened.st_ino == pathMetadata.st_ino,
              CredentialMigrationFileSecurity.descriptorHasNoExtendedACL(descriptor) else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
        return HarnessRuntimeSandboxDirectoryIdentity(
            url: url,
            device: UInt64(truncatingIfNeeded: opened.st_dev),
            inode: UInt64(truncatingIfNeeded: opened.st_ino),
            owner: opened.st_uid,
            permissions: UInt16(opened.st_mode & 0o7777)
        )
    }

    func revalidate() throws {
        guard try Self.capture(url) == self else {
            throw HarnessRuntimeWriteSandboxError.unsafeRoot
        }
    }
}

private struct HarnessRuntimeSandboxExecutableIdentity: Equatable {
    let url: URL
    let device: UInt64
    let inode: UInt64
    let owner: UInt32
    let permissions: UInt16
    let byteCount: Int64
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64

    static func capture(_ url: URL) throws -> HarnessRuntimeSandboxExecutableIdentity {
        var metadata = stat()
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == 0,
              metadata.st_nlink == 1,
              metadata.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0 else {
            throw HarnessRuntimeWriteSandboxError.unavailable
        }
        return HarnessRuntimeSandboxExecutableIdentity(
            url: url,
            device: UInt64(truncatingIfNeeded: metadata.st_dev),
            inode: UInt64(truncatingIfNeeded: metadata.st_ino),
            owner: metadata.st_uid,
            permissions: UInt16(metadata.st_mode & 0o7777),
            byteCount: Int64(metadata.st_size),
            modifiedSeconds: Int64(metadata.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(metadata.st_mtimespec.tv_nsec)
        )
    }

    func revalidate() throws {
        guard try Self.capture(url) == self else {
            throw HarnessRuntimeWriteSandboxError.unavailable
        }
    }
}
