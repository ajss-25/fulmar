import CryptoKit
import Darwin
import Foundation

enum MCPTrustStoreError: Error, Equatable, LocalizedError {
    case invalidIdentifier
    case invalidDisplayName
    case unsupportedTransport
    case invalidExecutablePath
    case executableNotFound
    case executableTooLarge
    case unsafeExecutable
    case shellExecutableForbidden
    case dynamicShebangInterpreterForbidden
    case nestedScriptInterpreterForbidden
    case invalidArguments
    case suspectedSecretArgument
    case unreviewedRuntimeEntrypoint
    case invalidWorkingDirectory
    case invalidEnvironment
    case invalidCredentialReference
    case invalidProviderPolicy
    case invalidDisclosure
    case invalidLimits
    case invalidReconnectPolicy
    case invalidProject
    case projectNotAllowed
    case providerNotAllowed
    case duplicateServerName
    case recordNotFound
    case notTrusted
    case trustRevoked
    case insecureStorage
    case corruptStore
    case unsupportedStoreVersion
    case storeTooLarge
    case tooManyServers

    var errorDescription: String? {
        switch self {
        case .invalidIdentifier: return "The MCP server identifier is invalid."
        case .invalidDisplayName: return "The MCP server display name is invalid."
        case .unsupportedTransport: return "Only local stdio MCP servers are supported."
        case .invalidExecutablePath: return "Choose an explicit absolute executable path."
        case .executableNotFound: return "The reviewed MCP executable could not be read."
        case .executableTooLarge: return "The reviewed executable or entry point exceeds the safety limit."
        case .unsafeExecutable: return "The MCP executable path, ownership, or permissions are unsafe."
        case .shellExecutableForbidden: return "Shell executables cannot be used as MCP server commands."
        case .dynamicShebangInterpreterForbidden: return "Scripts using an environment-selected interpreter are not allowed."
        case .nestedScriptInterpreterForbidden: return "The script interpreter must be a directly executable binary."
        case .invalidArguments: return "The reviewed MCP argument list is invalid."
        case .suspectedSecretArgument: return "Secrets cannot be placed in persisted MCP arguments."
        case .unreviewedRuntimeEntrypoint: return "Runtime entry-point files must be explicitly marked for fingerprint review."
        case .invalidWorkingDirectory: return "The MCP working directory must stay inside the approved project."
        case .invalidEnvironment: return "The MCP environment allowlist contains an unsafe variable."
        case .invalidCredentialReference: return "The MCP environment must contain credential references, never secret values."
        case .invalidProviderPolicy: return "Choose at least one exact provider boundary for this MCP server."
        case .invalidDisclosure: return "The MCP disclosure classification is incomplete or invalid."
        case .invalidLimits: return "The MCP resource limits are outside the supported safety range."
        case .invalidReconnectPolicy: return "The MCP reconnect policy is invalid."
        case .invalidProject: return "The project directory is missing or has unsafe ownership or permissions."
        case .projectNotAllowed: return "This MCP server was not approved for the active project."
        case .providerNotAllowed: return "This MCP server was not approved for the active model provider and data boundary."
        case .duplicateServerName: return "Every enabled MCP server must use a unique tool namespace."
        case .recordNotFound: return "The MCP server is not registered."
        case .notTrusted: return "Review and approve this MCP server before enabling it."
        case .trustRevoked: return "The MCP executable, entry point, project, or reviewed configuration changed; trust was revoked."
        case .insecureStorage: return "The MCP trust store is not an owner-only regular file."
        case .corruptStore: return "The MCP trust store is corrupt and was not reset."
        case .unsupportedStoreVersion: return "The MCP trust store was written by an unsupported version."
        case .storeTooLarge: return "The MCP trust store exceeds its safety limit."
        case .tooManyServers: return "The MCP server catalog has reached its safety limit."
        }
    }
}

private enum MCPTrustConstants {
    static let schemaVersion = 1
    static let maximumServers = 64
    static let maximumStoreBytes = 2 * 1_024 * 1_024
    static let maximumExecutableBytes: UInt64 = 512 * 1_024 * 1_024
    static let maximumReviewedArgumentFileBytes: UInt64 = 256 * 1_024 * 1_024
}

private struct MCPTrustEnvelope: Codable {
    let schemaVersion: Int
    var records: [String: MCPServerTrustRecord]

    init(records: [String: MCPServerTrustRecord]) {
        schemaVersion = MCPTrustConstants.schemaVersion
        self.records = records
    }

    private enum CodingKeys: String, CodingKey { case schemaVersion, records }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == MCPTrustConstants.schemaVersion else {
            throw MCPTrustStoreError.unsupportedStoreVersion
        }
        schemaVersion = version
        records = try container.decode([String: MCPServerTrustRecord].self, forKey: .records)
    }
}

private struct MCPSecureFileSnapshot {
    let canonicalPath: String
    let contentSHA256: String
    let byteCount: UInt64
    let ownerUID: UInt32
    let permissions: UInt16
    let firstBytes: Data
}

enum MCPExecutableInspector {
    static func inspect(
        _ executableURL: URL,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> MCPExecutableAudit {
        try preparationBudget?.checkpoint()
        guard executableURL.isFileURL,
              executableURL.path.hasPrefix("/"),
              !executableURL.path.contains("\0") else {
            throw MCPTrustStoreError.invalidExecutablePath
        }
        try MCPPathSecurity.validateDeclaredChain(executableURL)
        let snapshot = try MCPPathSecurity.secureSnapshot(
            executableURL,
            maximumBytes: MCPTrustConstants.maximumExecutableBytes,
            mustBeExecutable: true,
            preparationBudget: preparationBudget
        )
        try rejectForbiddenExecutable(snapshot.canonicalPath)

        var interpreterPath: String?
        var interpreterDigest: String?
        if let declaredInterpreter = try shebangInterpreter(in: snapshot.firstBytes) {
            guard declaredInterpreter != "/usr/bin/env" else {
                throw MCPTrustStoreError.dynamicShebangInterpreterForbidden
            }
            let interpreterURL = URL(fileURLWithPath: declaredInterpreter)
            try MCPPathSecurity.validateDeclaredChain(interpreterURL)
            let interpreter = try MCPPathSecurity.secureSnapshot(
                interpreterURL,
                maximumBytes: MCPTrustConstants.maximumExecutableBytes,
                mustBeExecutable: true,
                preparationBudget: preparationBudget
            )
            try rejectForbiddenExecutable(interpreter.canonicalPath)
            if try shebangInterpreter(in: interpreter.firstBytes) != nil {
                throw MCPTrustStoreError.nestedScriptInterpreterForbidden
            }
            interpreterPath = interpreter.canonicalPath
            interpreterDigest = interpreter.contentSHA256
        }

        var hasher = SHA256()
        MCPFingerprinting.add("local-harness-mcp-executable-v1", to: &hasher)
        MCPFingerprinting.add(snapshot.canonicalPath, to: &hasher)
        MCPFingerprinting.add(snapshot.contentSHA256, to: &hasher)
        MCPFingerprinting.add(String(snapshot.byteCount), to: &hasher)
        MCPFingerprinting.add(String(snapshot.ownerUID), to: &hasher)
        MCPFingerprinting.add(String(snapshot.permissions), to: &hasher)
        MCPFingerprinting.add(interpreterPath ?? "", to: &hasher)
        MCPFingerprinting.add(interpreterDigest ?? "", to: &hasher)

        return MCPExecutableAudit(
            declaredPath: executableURL.path,
            canonicalPath: snapshot.canonicalPath,
            contentSHA256: snapshot.contentSHA256,
            byteCount: snapshot.byteCount,
            ownerUID: snapshot.ownerUID,
            permissions: snapshot.permissions,
            interpreterCanonicalPath: interpreterPath,
            interpreterContentSHA256: interpreterDigest,
            fingerprint: MCPExecutableFingerprint(MCPFingerprinting.finish(hasher))
        )
    }

    static func inspectReviewedArgumentFile(
        path: String,
        index: Int,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> MCPReviewedArgumentFileAudit {
        try preparationBudget?.checkpoint()
        guard path.hasPrefix("/"), !path.contains("\0") else {
            throw MCPTrustStoreError.invalidArguments
        }
        let url = URL(fileURLWithPath: path)
        try MCPPathSecurity.validateDeclaredChain(url)
        let snapshot = try MCPPathSecurity.secureSnapshot(
            url,
            maximumBytes: MCPTrustConstants.maximumReviewedArgumentFileBytes,
            mustBeExecutable: false,
            preparationBudget: preparationBudget
        )
        return MCPReviewedArgumentFileAudit(
            argumentIndex: index,
            declaredPath: path,
            canonicalPath: snapshot.canonicalPath,
            contentSHA256: snapshot.contentSHA256,
            byteCount: snapshot.byteCount,
            ownerUID: snapshot.ownerUID,
            permissions: snapshot.permissions
        )
    }

    private static func rejectForbiddenExecutable(_ path: String) throws {
        let basename = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        let forbidden: Set<String> = [
            "ash", "bash", "csh", "cmd", "cmd.exe", "dash", "env", "fish",
            "ksh", "powershell", "powershell.exe", "pwsh", "sh", "tcsh", "zsh"
        ]
        guard !forbidden.contains(basename) else {
            throw MCPTrustStoreError.shellExecutableForbidden
        }
    }

    private static func shebangInterpreter(in prefix: Data) throws -> String? {
        guard prefix.count >= 2,
              prefix[prefix.startIndex] == 0x23,
              prefix[prefix.index(after: prefix.startIndex)] == 0x21 else { return nil }
        let lineData = prefix.prefix { $0 != 0x0A && $0 != 0x0D }
        guard let line = String(data: lineData, encoding: .utf8) else {
            throw MCPTrustStoreError.unsafeExecutable
        }
        let specification = line.dropFirst(2).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let token = specification.split(whereSeparator: { $0 == " " || $0 == "\t" }).first,
              token.hasPrefix("/") else {
            throw MCPTrustStoreError.dynamicShebangInterpreterForbidden
        }
        return String(token)
    }
}

enum MCPProjectInspector {
    static func inspect(_ projectRoot: URL) throws -> MCPProjectIdentity {
        guard projectRoot.isFileURL,
              projectRoot.path.hasPrefix("/"),
              !projectRoot.path.contains("\0") else {
            throw MCPTrustStoreError.invalidProject
        }
        do {
            try MCPPathSecurity.validateDeclaredChain(projectRoot)
            let canonical = try MCPPathSecurity.canonicalPath(for: projectRoot)
            var metadata = stat()
            guard Darwin.lstat(canonical, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == getuid(),
                  metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
                throw MCPTrustStoreError.invalidProject
            }
            var hasher = SHA256()
            MCPFingerprinting.add("local-harness-mcp-project-v1", to: &hasher)
            MCPFingerprinting.add(canonical, to: &hasher)
            MCPFingerprinting.add(String(UInt64(truncatingIfNeeded: metadata.st_dev)), to: &hasher)
            MCPFingerprinting.add(String(UInt64(truncatingIfNeeded: metadata.st_ino)), to: &hasher)
            MCPFingerprinting.add(String(metadata.st_uid), to: &hasher)
            return MCPProjectIdentity(
                canonicalPath: canonical,
                ownerUID: metadata.st_uid,
                deviceID: UInt64(truncatingIfNeeded: metadata.st_dev),
                inode: UInt64(truncatingIfNeeded: metadata.st_ino),
                fingerprint: MCPFingerprinting.finish(hasher)
            )
        } catch let error as MCPTrustStoreError {
            throw error
        } catch {
            throw MCPTrustStoreError.invalidProject
        }
    }
}

private enum MCPDraftValidator {
    private static let identifierPattern = try! NSRegularExpression(pattern: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#)
    private static let serverNamePattern = try! NSRegularExpression(pattern: #"^[A-Za-z0-9_-]{1,32}$"#)
    private static let environmentPattern = try! NSRegularExpression(pattern: #"^[A-Z][A-Z0-9_]{0,63}$"#)
    private static let credentialPattern = try! NSRegularExpression(pattern: #"^[A-Z][A-Z0-9_]{0,95}$"#)

    static func validate(_ draft: MCPServerDraft) throws {
        guard matches(draft.id, identifierPattern) else { throw MCPTrustStoreError.invalidIdentifier }
        guard !draft.displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              draft.displayName.utf8.count <= 100,
              draft.displayName.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw MCPTrustStoreError.invalidDisplayName
        }
        guard draft.transport == .stdio else { throw MCPTrustStoreError.unsupportedTransport }
        guard matches(draft.serverName, serverNamePattern) else { throw MCPTrustStoreError.invalidIdentifier }
        guard draft.executablePath.hasPrefix("/"),
              draft.executablePath.utf8.count <= 4_096,
              !draft.executablePath.contains("\0") else {
            throw MCPTrustStoreError.invalidExecutablePath
        }
        try validateArguments(draft)
        try validateWorkingDirectory(draft.projectRelativeWorkingDirectory)
        try validateEnvironment(draft.environment, disclosure: draft.disclosure)
        try validateProviders(draft.allowedProviders)
        try validateDisclosure(draft.disclosure)
        try validateLimits(draft.limits)
        try validateReconnect(draft.reconnect)
    }

    static func validateRuntimeShape(_ draft: MCPServerDraft, executable: MCPExecutableAudit) throws {
        let basename = URL(fileURLWithPath: executable.canonicalPath).lastPathComponent.lowercased()
        let runtime = basename == "node" || basename == "nodejs" || basename == "deno" || basename == "bun"
            || basename == "java" || basename == "ruby" || basename == "perl"
            || basename.hasPrefix("python")
        if runtime && draft.reviewedFileArgumentIndexes.isEmpty {
            throw MCPTrustStoreError.unreviewedRuntimeEntrypoint
        }

        let forbiddenInlineFlags: Set<String>
        if basename == "node" || basename == "nodejs" {
            forbiddenInlineFlags = ["-e", "--eval", "-p", "--print"]
        } else if basename.hasPrefix("python") {
            forbiddenInlineFlags = ["-c"]
        } else if basename == "ruby" || basename == "perl" {
            forbiddenInlineFlags = ["-e"]
        } else {
            forbiddenInlineFlags = []
        }
        guard !draft.arguments.contains(where: forbiddenInlineFlags.contains) else {
            throw MCPTrustStoreError.invalidArguments
        }
    }

    static func resolvedWorkingDirectory(_ relative: String?, project: MCPProjectIdentity) throws -> String {
        let projectURL = URL(fileURLWithPath: project.canonicalPath, isDirectory: true)
        let candidate = relative.map { projectURL.appendingPathComponent($0, isDirectory: true) } ?? projectURL
        let canonical: String
        do { canonical = try MCPPathSecurity.canonicalPath(for: candidate) }
        catch { throw MCPTrustStoreError.invalidWorkingDirectory }
        let prefix = project.canonicalPath.hasSuffix("/") ? project.canonicalPath : project.canonicalPath + "/"
        guard canonical == project.canonicalPath || canonical.hasPrefix(prefix) else {
            throw MCPTrustStoreError.invalidWorkingDirectory
        }
        var metadata = stat()
        guard Darwin.lstat(canonical, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              (metadata.st_uid == getuid() || metadata.st_uid == 0),
              metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
            throw MCPTrustStoreError.invalidWorkingDirectory
        }
        return canonical
    }

    private static func validateArguments(_ draft: MCPServerDraft) throws {
        guard draft.arguments.count <= 64,
              draft.arguments.reduce(0, { $0 + $1.utf8.count }) <= 16_384,
              draft.arguments.allSatisfy({
                  $0.utf8.count <= 4_096 && !$0.contains("\0") && !$0.contains("\n") && !$0.contains("\r")
              }) else {
            throw MCPTrustStoreError.invalidArguments
        }
        let sensitiveFlag = try! NSRegularExpression(
            pattern: #"(?i)^--?(?:api[-_]?key|password|secret|token|access[-_]?token)(?:=|$)"#
        )
        for argument in draft.arguments where matches(argument, sensitiveFlag) {
            throw MCPTrustStoreError.suspectedSecretArgument
        }

        let indexes = draft.reviewedFileArgumentIndexes
        guard indexes.count <= 16,
              Set(indexes).count == indexes.count,
              indexes.allSatisfy({ draft.arguments.indices.contains($0) && draft.arguments[$0].hasPrefix("/") }) else {
            throw MCPTrustStoreError.invalidArguments
        }
        let codeExtensions: Set<String> = ["js", "mjs", "cjs", "ts", "py", "rb", "pl", "jar"]
        for (index, argument) in draft.arguments.enumerated()
            where codeExtensions.contains(URL(fileURLWithPath: argument).pathExtension.lowercased()) {
            guard argument.hasPrefix("/"), indexes.contains(index) else {
                throw MCPTrustStoreError.unreviewedRuntimeEntrypoint
            }
        }
    }

    private static func validateWorkingDirectory(_ relative: String?) throws {
        guard let relative else { return }
        guard !relative.isEmpty,
              !relative.hasPrefix("/"),
              relative.utf8.count <= 1_024,
              !relative.contains("\0") else {
            throw MCPTrustStoreError.invalidWorkingDirectory
        }
        let components = NSString(string: relative).pathComponents
        guard components.allSatisfy({ $0 != "." && $0 != ".." && $0 != "/" }) else {
            throw MCPTrustStoreError.invalidWorkingDirectory
        }
    }

    private static func validateEnvironment(
        _ environment: [MCPEnvironmentBinding],
        disclosure: MCPDisclosureProfile
    ) throws {
        guard environment.count <= 12,
              Set(environment.map(\.variableName)).count == environment.count else {
            throw MCPTrustStoreError.invalidEnvironment
        }
        let forbiddenExact: Set<String> = [
            "BASH_ENV", "ENV", "HOME", "IFS", "LANG", "LOGNAME", "NODE_OPTIONS", "PATH", "PERL5OPT",
            "PYTHONHOME", "PYTHONPATH", "RUBYOPT", "SHELL", "TMPDIR", "USER", "ZDOTDIR"
        ]
        for binding in environment {
            guard matches(binding.variableName, environmentPattern),
                  !forbiddenExact.contains(binding.variableName),
                  !binding.variableName.hasPrefix("DSH_"),
                  !binding.variableName.hasPrefix("DYLD_"),
                  !binding.variableName.hasPrefix("LD_"),
                  !binding.variableName.hasPrefix("LOCAL_HARNESS_") else {
                throw MCPTrustStoreError.invalidEnvironment
            }
            guard matches(binding.credential.rawValue, credentialPattern) else {
                throw MCPTrustStoreError.invalidCredentialReference
            }
        }
        if !environment.isEmpty,
           !disclosure.dataKinds.contains(.authenticationMetadata) {
            throw MCPTrustStoreError.invalidDisclosure
        }
    }

    private static func validateProviders(_ providers: [MCPProviderEnablement]) throws {
        guard !providers.isEmpty,
              providers.count <= 16,
              Set(providers.map(\.provider)).count == providers.count,
              providers.allSatisfy({
                  !$0.provider.rawValue.isEmpty
                      && $0.provider.rawValue.utf8.count <= 128
                      && !$0.provider.rawValue.contains("\0")
                      && !$0.provider.rawValue.contains("\n")
              }) else {
            throw MCPTrustStoreError.invalidProviderPolicy
        }
    }

    private static func validateDisclosure(_ disclosure: MCPDisclosureProfile) throws {
        guard !disclosure.dataKinds.isEmpty,
              Set(disclosure.dataKinds).count == disclosure.dataKinds.count else {
            throw MCPTrustStoreError.invalidDisclosure
        }
        let name = disclosure.destinationName?.trimmingCharacters(in: .whitespacesAndNewlines)
        // The current MCP execution boundary is deliberately local-only even
        // when the selected model provider is cloud or local-network. A future
        // network-capable MCP product must introduce a separate sandbox and
        // consent contract rather than reusing this stdio trust decision.
        guard disclosure.boundary == .onDevice else {
            throw MCPTrustStoreError.invalidDisclosure
        }
        if let name, !name.isEmpty {
            throw MCPTrustStoreError.invalidDisclosure
        }
    }

    private static func validateLimits(_ limits: MCPExecutionLimits) throws {
        guard (1_000...60_000).contains(limits.startupTimeoutMilliseconds),
              (1_000...120_000).contains(limits.toolCallTimeoutMilliseconds),
              (1...128).contains(limits.maximumDiscoveredTools),
              (1_024...4 * 1_024 * 1_024).contains(limits.maximumOutputBytes) else {
            throw MCPTrustStoreError.invalidLimits
        }
    }

    private static func validateReconnect(_ reconnect: MCPReconnectConfiguration) throws {
        guard (100...60_000).contains(reconnect.initialDelayMilliseconds),
              (reconnect.initialDelayMilliseconds...120_000).contains(reconnect.maximumDelayMilliseconds),
              (1...20).contains(reconnect.maximumAttempts) else {
            throw MCPTrustStoreError.invalidReconnectPolicy
        }
    }

    private static func matches(_ value: String, _ expression: NSRegularExpression) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range)?.range == range
    }
}

final class MCPTrustStore {
    static let stateFilename = "mcp-trust-v1.json"

    private let fileManager: FileManager
    private let securityDirectory: URL
    private let stateURL: URL
    private let now: () -> Date
    private var recordsByID: [String: MCPServerTrustRecord]

    init(
        applicationSupport: URL,
        fileManager: FileManager = .default,
        now: @escaping () -> Date = Date.init
    ) throws {
        self.fileManager = fileManager
        self.now = now
        securityDirectory = applicationSupport.appendingPathComponent("Security", isDirectory: true)
        stateURL = securityDirectory.appendingPathComponent(Self.stateFilename, isDirectory: false)
        try Self.preparePrivateStorage(
            applicationSupport: applicationSupport,
            securityDirectory: securityDirectory,
            fileManager: fileManager
        )
        recordsByID = try Self.load(from: stateURL)
        try validateLoadedState()
    }

    func records() -> [MCPServerTrustRecord] {
        recordsByID.values.sorted { $0.draft.displayName.localizedCaseInsensitiveCompare($1.draft.displayName) == .orderedAscending }
    }

    func record(id: String) -> MCPServerTrustRecord? { recordsByID[id] }

    /// Save a definition as a draft. Any material change clears an existing
    /// approval; an identical save preserves it.
    @discardableResult
    func saveDraft(_ draft: MCPServerDraft, projectRoot: URL) throws -> MCPServerTrustRecord {
        try MCPDraftValidator.validate(draft)
        guard recordsByID.count < MCPTrustConstants.maximumServers || recordsByID[draft.id] != nil else {
            throw MCPTrustStoreError.tooManyServers
        }
        guard !recordsByID.values.contains(where: { $0.id != draft.id && $0.draft.serverName == draft.serverName }) else {
            throw MCPTrustStoreError.duplicateServerName
        }
        let project = try MCPProjectInspector.inspect(projectRoot)
        _ = try MCPDraftValidator.resolvedWorkingDirectory(
            draft.projectRelativeWorkingDirectory,
            project: project
        )
        let executable = try MCPExecutableInspector.inspect(URL(fileURLWithPath: draft.executablePath))
        try MCPDraftValidator.validateRuntimeShape(draft, executable: executable)
        let argumentFiles = try inspectArgumentFiles(draft)
        let fingerprint = MCPFingerprinting.reviewFingerprint(
            draft: draft,
            project: project,
            executable: executable,
            argumentFiles: argumentFiles
        )
        let previousApproval = recordsByID[draft.id]?.approval
        let retainedApproval = previousApproval?.reviewFingerprint == fingerprint ? previousApproval : nil
        let record = MCPServerTrustRecord(
            id: draft.id,
            draft: draft,
            project: project,
            approval: retainedApproval,
            updatedAt: now()
        )
        var next = recordsByID
        next[draft.id] = record
        try persist(next)
        recordsByID = next
        return record
    }

    /// Approving always re-reads the executable and reviewed argument files.
    /// The returned fingerprint is suitable for a final review confirmation.
    @discardableResult
    func approve(id: String) throws -> MCPServerTrustRecord {
        guard let existing = recordsByID[id] else { throw MCPTrustStoreError.recordNotFound }
        try MCPDraftValidator.validate(existing.draft)
        let project = try MCPProjectInspector.inspect(URL(fileURLWithPath: existing.project.canonicalPath))
        _ = try MCPDraftValidator.resolvedWorkingDirectory(
            existing.draft.projectRelativeWorkingDirectory,
            project: project
        )
        let executable = try MCPExecutableInspector.inspect(URL(fileURLWithPath: existing.draft.executablePath))
        try MCPDraftValidator.validateRuntimeShape(existing.draft, executable: executable)
        let argumentFiles = try inspectArgumentFiles(existing.draft)
        let fingerprint = MCPFingerprinting.reviewFingerprint(
            draft: existing.draft,
            project: project,
            executable: executable,
            argumentFiles: argumentFiles
        )
        let record = MCPServerTrustRecord(
            id: existing.id,
            draft: existing.draft,
            project: project,
            approval: MCPTrustApproval(
                reviewFingerprint: fingerprint,
                executableFingerprint: executable.fingerprint,
                approvedAt: now()
            ),
            updatedAt: now()
        )
        var next = recordsByID
        next[id] = record
        try persist(next)
        recordsByID = next
        return record
    }

    func revoke(id: String) throws {
        guard var record = recordsByID[id] else { throw MCPTrustStoreError.recordNotFound }
        record.approval = nil
        record.updatedAt = now()
        var next = recordsByID
        next[id] = record
        try persist(next)
        recordsByID = next
    }

    func remove(id: String) throws {
        var next = recordsByID
        guard next.removeValue(forKey: id) != nil else { throw MCPTrustStoreError.recordNotFound }
        try persist(next)
        recordsByID = next
    }

    func status(id: String) throws -> MCPTrustStatus {
        guard let record = recordsByID[id] else { throw MCPTrustStoreError.recordNotFound }
        guard let approval = record.approval else { return .unreviewed }
        do {
            let project = try MCPProjectInspector.inspect(URL(fileURLWithPath: record.project.canonicalPath))
            let executable = try MCPExecutableInspector.inspect(URL(fileURLWithPath: record.draft.executablePath))
            try MCPDraftValidator.validateRuntimeShape(record.draft, executable: executable)
            let arguments = try inspectArgumentFiles(record.draft)
            let fingerprint = MCPFingerprinting.reviewFingerprint(
                draft: record.draft,
                project: project,
                executable: executable,
                argumentFiles: arguments
            )
            if fingerprint == approval.reviewFingerprint,
               executable.fingerprint == approval.executableFingerprint,
               project == record.project {
                return .trusted
            }
        } catch {
            try revokeChangedRecord(id: id)
            return .changed
        }
        try revokeChangedRecord(id: id)
        return .changed
    }

    /// Produces an activation plan but deliberately performs no process launch
    /// and no DSH settings mutation.
    func activationPlan(
        id: String,
        context: MCPActivationContext,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> MCPActivationPlan {
        try preparationBudget?.checkpoint()
        guard let record = recordsByID[id] else { throw MCPTrustStoreError.recordNotFound }
        guard let approval = record.approval else { throw MCPTrustStoreError.notTrusted }
        let activeProject = try MCPProjectInspector.inspect(context.projectRoot)
        guard activeProject.canonicalPath == record.project.canonicalPath else {
            throw MCPTrustStoreError.projectNotAllowed
        }
        guard activeProject == record.project else {
            try revokeChangedRecord(id: id)
            throw MCPTrustStoreError.trustRevoked
        }
        guard record.draft.allowedProviders.contains(where: {
            $0.provider == context.provider && $0.boundary == context.providerBoundary
        }) else {
            throw MCPTrustStoreError.providerNotAllowed
        }

        do {
            try MCPDraftValidator.validate(record.draft)
            let executable = try MCPExecutableInspector.inspect(
                URL(fileURLWithPath: record.draft.executablePath),
                preparationBudget: preparationBudget
            )
            try MCPDraftValidator.validateRuntimeShape(record.draft, executable: executable)
            let argumentFiles = try inspectArgumentFiles(
                record.draft,
                preparationBudget: preparationBudget
            )
            let currentFingerprint = MCPFingerprinting.reviewFingerprint(
                draft: record.draft,
                project: activeProject,
                executable: executable,
                argumentFiles: argumentFiles
            )
            guard currentFingerprint == approval.reviewFingerprint,
                  executable.fingerprint == approval.executableFingerprint else {
                try revokeChangedRecord(id: id)
                throw MCPTrustStoreError.trustRevoked
            }
            let workingDirectory = try MCPDraftValidator.resolvedWorkingDirectory(
                record.draft.projectRelativeWorkingDirectory,
                project: activeProject
            )
            return MCPActivationPlan(
                serverID: record.id,
                reviewFingerprint: currentFingerprint,
                executable: executable,
                reviewedArgumentFiles: argumentFiles,
                project: activeProject,
                dsh: MCPDSHStdioPluginPlan(
                    pluginID: "mcp-\(record.draft.serverName)",
                    packageName: MCPDSHStdioPluginPlan.packageName,
                    transport: .stdio,
                    serverName: record.draft.serverName,
                    command: executable.canonicalPath,
                    arguments: record.draft.arguments,
                    environment: record.draft.environment
                        .sorted { $0.variableName < $1.variableName }
                        .map { MCPDSHEnvironmentReference(variableName: $0.variableName, credential: $0.credential) },
                    workingDirectory: workingDirectory,
                    toolCallTimeoutMilliseconds: record.draft.limits.toolCallTimeoutMilliseconds,
                    failOnStartupError: true,
                    reconnect: MCPDSHReconnectPlan(
                        enabled: record.draft.reconnect.enabled,
                        initialDelayMilliseconds: record.draft.reconnect.initialDelayMilliseconds,
                        maximumDelayMilliseconds: record.draft.reconnect.maximumDelayMilliseconds,
                        maximumAttempts: record.draft.reconnect.maximumAttempts
                    )
                ),
                wrapper: MCPWrapperEnforcementPlan(
                    startupTimeoutMilliseconds: record.draft.limits.startupTimeoutMilliseconds,
                    maximumDiscoveredTools: record.draft.limits.maximumDiscoveredTools,
                    maximumOutputBytes: record.draft.limits.maximumOutputBytes,
                    inheritAmbientEnvironment: false
                ),
                disclosure: MCPActivationDisclosure(
                    mcpServer: record.draft.disclosure,
                    modelProvider: context.provider,
                    modelBoundary: context.providerBoundary
                )
            )
        } catch MCPTrustStoreError.trustRevoked {
            throw MCPTrustStoreError.trustRevoked
        } catch let error as RuntimeStartupPrerequisiteError {
            throw error
        } catch {
            try revokeChangedRecord(id: id)
            throw MCPTrustStoreError.trustRevoked
        }
    }

    private func inspectArgumentFiles(
        _ draft: MCPServerDraft,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> [MCPReviewedArgumentFileAudit] {
        try draft.reviewedFileArgumentIndexes.sorted().map { index in
            try preparationBudget?.checkpoint()
            return try MCPExecutableInspector.inspectReviewedArgumentFile(
                path: draft.arguments[index],
                index: index,
                preparationBudget: preparationBudget
            )
        }
    }

    private func revokeChangedRecord(id: String) throws {
        guard var record = recordsByID[id] else { return }
        record.approval = nil
        record.updatedAt = now()
        var next = recordsByID
        next[id] = record
        try persist(next)
        recordsByID = next
    }

    private func validateLoadedState() throws {
        guard recordsByID.count <= MCPTrustConstants.maximumServers else {
            throw MCPTrustStoreError.tooManyServers
        }
        var namespaces = Set<String>()
        for (key, record) in recordsByID {
            guard key == record.id, key == record.draft.id else { throw MCPTrustStoreError.corruptStore }
            do { try MCPDraftValidator.validate(record.draft) }
            catch { throw MCPTrustStoreError.corruptStore }
            guard namespaces.insert(record.draft.serverName).inserted,
                  record.project.canonicalPath.hasPrefix("/"),
                  MCPFingerprinting.isSHA256(record.project.fingerprint) else {
                throw MCPTrustStoreError.corruptStore
            }
            if let approval = record.approval {
                guard MCPFingerprinting.isSHA256(approval.reviewFingerprint),
                      MCPFingerprinting.isSHA256(approval.executableFingerprint.rawValue) else {
                    throw MCPTrustStoreError.corruptStore
                }
            }
        }
    }

    private func persist(_ records: [String: MCPServerTrustRecord]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(MCPTrustEnvelope(records: records))
        guard data.count <= MCPTrustConstants.maximumStoreBytes else { throw MCPTrustStoreError.storeTooLarge }
        try Self.atomicOwnerOnlyWrite(data, to: stateURL, directory: securityDirectory)
    }

    private static func preparePrivateStorage(
        applicationSupport: URL,
        securityDirectory: URL,
        fileManager: FileManager
    ) throws {
        if !fileManager.fileExists(atPath: applicationSupport.path) {
            try fileManager.createDirectory(
                at: applicationSupport,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try validateOwnedDirectory(applicationSupport, requirePrivate: false)
        if !fileManager.fileExists(atPath: securityDirectory.path) {
            guard Darwin.mkdir(securityDirectory.path, 0o700) == 0 else {
                throw MCPTrustStoreError.insecureStorage
            }
        }
        try validateOwnedDirectory(securityDirectory, requirePrivate: true)
        guard Darwin.chmod(securityDirectory.path, 0o700) == 0 else {
            throw MCPTrustStoreError.insecureStorage
        }
    }

    private static func validateOwnedDirectory(_ url: URL, requirePrivate: Bool) throws {
        var metadata = stat()
        let forbiddenPermissions: mode_t = requirePrivate
            ? (S_IRWXG | S_IRWXO)
            : (S_IWGRP | S_IWOTH)
        guard Darwin.lstat(url.path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == getuid(),
              metadata.st_mode & forbiddenPermissions == 0 else {
            throw MCPTrustStoreError.insecureStorage
        }
    }

    private static func load(from url: URL) throws -> [String: MCPServerTrustRecord] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        let data = try readOwnerOnlyFile(url)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        do {
            return try decoder.decode(MCPTrustEnvelope.self, from: data).records
        } catch let error as MCPTrustStoreError {
            throw error
        } catch {
            throw MCPTrustStoreError.corruptStore
        }
    }

    private static func readOwnerOnlyFile(_ url: URL) throws -> Data {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw MCPTrustStoreError.insecureStorage }
        defer { _ = Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == getuid(),
              metadata.st_mode & (S_IRWXG | S_IRWXO) == 0,
              metadata.st_size >= 0 else {
            throw MCPTrustStoreError.insecureStorage
        }
        guard metadata.st_size <= MCPTrustConstants.maximumStoreBytes else {
            throw MCPTrustStoreError.storeTooLarge
        }
        var result = Data()
        result.reserveCapacity(Int(metadata.st_size))
        var buffer = [UInt8](repeating: 0, count: 32 * 1_024)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            guard count >= 0 else { throw MCPTrustStoreError.insecureStorage }
            if count == 0 { break }
            result.append(contentsOf: buffer.prefix(count))
            guard result.count <= MCPTrustConstants.maximumStoreBytes else {
                throw MCPTrustStoreError.storeTooLarge
            }
        }
        return result
    }

    private static func atomicOwnerOnlyWrite(_ data: Data, to destination: URL, directory: URL) throws {
        try validateOwnedDirectory(directory, requirePrivate: true)
        if FileManager.default.fileExists(atPath: destination.path) {
            var existing = stat()
            guard Darwin.lstat(destination.path, &existing) == 0,
                  existing.st_mode & S_IFMT == S_IFREG,
                  existing.st_uid == getuid(),
                  existing.st_mode & (S_IRWXG | S_IRWXO) == 0 else {
                throw MCPTrustStoreError.insecureStorage
            }
        }
        let temporary = directory.appendingPathComponent(".mcp-trust-\(UUID().uuidString).tmp")
        let descriptor = Darwin.open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw MCPTrustStoreError.insecureStorage }
        var completed = false
        defer {
            _ = Darwin.close(descriptor)
            if !completed { _ = Darwin.unlink(temporary.path) }
        }
        let wroteAll = data.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return data.isEmpty }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        guard wroteAll,
              Darwin.fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
              Darwin.fsync(descriptor) == 0,
              Darwin.rename(temporary.path, destination.path) == 0 else {
            throw MCPTrustStoreError.insecureStorage
        }
        completed = true
        guard Darwin.chmod(destination.path, 0o600) == 0 else {
            throw MCPTrustStoreError.insecureStorage
        }
        let directoryDescriptor = Darwin.open(directory.path, O_RDONLY | O_CLOEXEC)
        if directoryDescriptor >= 0 {
            _ = Darwin.fsync(directoryDescriptor)
            _ = Darwin.close(directoryDescriptor)
        }
    }
}

private enum MCPPathSecurity {
    static func canonicalPath(for url: URL) throws -> String {
        guard let pointer = Darwin.realpath(url.path, nil) else {
            throw MCPTrustStoreError.executableNotFound
        }
        defer { Darwin.free(pointer) }
        return String(cString: pointer)
    }

    static func validateDeclaredChain(_ url: URL) throws {
        guard url.path.hasPrefix("/"), url.path.utf8.count <= 4_096 else {
            throw MCPTrustStoreError.invalidExecutablePath
        }
        var current = URL(fileURLWithPath: "/", isDirectory: true)
        let components = NSString(string: url.path).pathComponents.dropFirst()
        for (offset, component) in components.enumerated() {
            current.appendPathComponent(component)
            var metadata = stat()
            guard Darwin.lstat(current.path, &metadata) == 0,
                  metadata.st_uid == 0 || metadata.st_uid == getuid() else {
                throw MCPTrustStoreError.unsafeExecutable
            }
            let isFinal = offset == components.count - 1
            let kind = metadata.st_mode & S_IFMT
            if kind == S_IFDIR {
                try validateDirectoryMode(metadata)
            } else if kind == S_IFLNK {
                continue
            } else if !isFinal {
                throw MCPTrustStoreError.unsafeExecutable
            }
        }
    }

    static func secureSnapshot(
        _ declaredURL: URL,
        maximumBytes: UInt64,
        mustBeExecutable: Bool,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> MCPSecureFileSnapshot {
        try preparationBudget?.checkpoint()
        let canonical = try canonicalPath(for: declaredURL)
        try validateCanonicalParents(URL(fileURLWithPath: canonical))
        let descriptor = Darwin.open(canonical, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw MCPTrustStoreError.executableNotFound }
        defer { _ = Darwin.close(descriptor) }

        var before = stat()
        guard Darwin.fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == 0 || before.st_uid == getuid(),
              before.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0,
              before.st_size >= 0 else {
            throw MCPTrustStoreError.unsafeExecutable
        }
        if mustBeExecutable {
            guard before.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0,
                  Darwin.access(canonical, X_OK) == 0 else {
                throw MCPTrustStoreError.unsafeExecutable
            }
        }
        let byteCount = UInt64(before.st_size)
        guard byteCount <= maximumBytes else { throw MCPTrustStoreError.executableTooLarge }

        var hasher = SHA256()
        var prefix = Data()
        var total: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            try preparationBudget?.checkpoint()
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress, bytes.count)
            }
            guard count >= 0 else { throw MCPTrustStoreError.executableNotFound }
            if count == 0 { break }
            let chunk = Data(buffer.prefix(count))
            hasher.update(data: chunk)
            if prefix.count < 512 { prefix.append(chunk.prefix(512 - prefix.count)) }
            total += UInt64(count)
            guard total <= maximumBytes else { throw MCPTrustStoreError.executableTooLarge }
        }

        try preparationBudget?.checkpoint()

        var after = stat()
        guard Darwin.fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              total == byteCount else {
            throw MCPTrustStoreError.unsafeExecutable
        }
        return MCPSecureFileSnapshot(
            canonicalPath: canonical,
            contentSHA256: MCPFingerprinting.finish(hasher),
            byteCount: byteCount,
            ownerUID: before.st_uid,
            permissions: UInt16(before.st_mode & 0o7777),
            firstBytes: prefix
        )
    }

    private static func validateCanonicalParents(_ file: URL) throws {
        var current = URL(fileURLWithPath: "/", isDirectory: true)
        let components = NSString(string: file.deletingLastPathComponent().path).pathComponents.dropFirst()
        for component in components {
            current.appendPathComponent(component, isDirectory: true)
            var metadata = stat()
            guard Darwin.lstat(current.path, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0 || metadata.st_uid == getuid() else {
                throw MCPTrustStoreError.unsafeExecutable
            }
            try validateDirectoryMode(metadata)
        }
    }

    private static func validateDirectoryMode(_ metadata: stat) throws {
        let writableByOthers = metadata.st_mode & (S_IWGRP | S_IWOTH) != 0
        let rootOwnedSticky = metadata.st_uid == 0 && metadata.st_mode & S_ISVTX != 0
        guard !writableByOthers || rootOwnedSticky else {
            throw MCPTrustStoreError.unsafeExecutable
        }
    }
}

private enum MCPFingerprinting {
    static func add(_ value: String, to hasher: inout SHA256) {
        let data = Data(value.utf8)
        var length = UInt64(data.count).bigEndian
        withUnsafeBytes(of: &length) { hasher.update(bufferPointer: $0) }
        hasher.update(data: data)
    }

    static func finish(_ hasher: SHA256) -> String {
        let copy = hasher
        return copy.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    static func reviewFingerprint(
        draft: MCPServerDraft,
        project: MCPProjectIdentity,
        executable: MCPExecutableAudit,
        argumentFiles: [MCPReviewedArgumentFileAudit]
    ) -> String {
        var hasher = SHA256()
        add("local-harness-mcp-review-v1", to: &hasher)
        add(draft.id, to: &hasher)
        add(draft.displayName, to: &hasher)
        add(draft.transport.rawValue, to: &hasher)
        add(draft.serverName, to: &hasher)
        add(draft.executablePath, to: &hasher)
        add(executable.fingerprint.rawValue, to: &hasher)
        for (index, argument) in draft.arguments.enumerated() {
            add(String(index), to: &hasher)
            add(argument, to: &hasher)
        }
        for file in argumentFiles.sorted(by: { $0.argumentIndex < $1.argumentIndex }) {
            add(String(file.argumentIndex), to: &hasher)
            add(file.canonicalPath, to: &hasher)
            add(file.contentSHA256, to: &hasher)
            add(String(file.byteCount), to: &hasher)
            add(String(file.ownerUID), to: &hasher)
            add(String(file.permissions), to: &hasher)
        }
        add(draft.projectRelativeWorkingDirectory ?? "", to: &hasher)
        for binding in draft.environment.sorted(by: { $0.variableName < $1.variableName }) {
            add(binding.variableName, to: &hasher)
            add(binding.credential.rawValue, to: &hasher)
        }
        for provider in draft.allowedProviders.sorted(by: {
            ($0.provider.rawValue, $0.boundary.rawValue) < ($1.provider.rawValue, $1.boundary.rawValue)
        }) {
            add(provider.provider.rawValue, to: &hasher)
            add(provider.boundary.rawValue, to: &hasher)
        }
        add(draft.disclosure.boundary.rawValue, to: &hasher)
        add(draft.disclosure.destinationName ?? "", to: &hasher)
        for kind in draft.disclosure.dataKinds.sorted(by: { $0.rawValue < $1.rawValue }) {
            add(kind.rawValue, to: &hasher)
        }
        add(String(draft.limits.startupTimeoutMilliseconds), to: &hasher)
        add(String(draft.limits.toolCallTimeoutMilliseconds), to: &hasher)
        add(String(draft.limits.maximumDiscoveredTools), to: &hasher)
        add(String(draft.limits.maximumOutputBytes), to: &hasher)
        add(String(draft.reconnect.enabled), to: &hasher)
        add(String(draft.reconnect.initialDelayMilliseconds), to: &hasher)
        add(String(draft.reconnect.maximumDelayMilliseconds), to: &hasher)
        add(String(draft.reconnect.maximumAttempts), to: &hasher)
        add(project.fingerprint, to: &hasher)
        return finish(hasher)
    }
}
