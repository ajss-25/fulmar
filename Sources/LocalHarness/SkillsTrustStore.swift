import CryptoKit
import Darwin
import Foundation

enum SkillsTrustStoreError: LocalizedError, Equatable {
    case unsafeStorage(String)
    case invalidBundle(String)
    case symbolicLink(String)
    case unsupportedEntry(String)
    case pathEscape(String)
    case tooManyFiles(Int)
    case tooManyEntries(Int)
    case enumerationTimedOut
    case fileTooLarge(String)
    case bundleTooLarge
    case skillLimitReached(Int)
    case policyLimitReached(Int)
    case invalidProjectIdentity
    case duplicateSkill(String)
    case skillNotFound(String)
    case corruptState
    case changedSinceImport(String)
    case ioFailure(String)

    var errorDescription: String? {
        switch self {
        case .unsafeStorage(let path): return "The private skill store is not a regular owner-only directory: \(path)."
        case .invalidBundle(let detail): return "This is not a valid, safely readable skill bundle: \(detail)."
        case .symbolicLink(let path): return "Symbolic links are not accepted in skill bundles: \(path)."
        case .unsupportedEntry(let path): return "Only regular files and directories are accepted in skill bundles: \(path)."
        case .pathEscape(let path): return "A skill entry escaped its selected bundle: \(path)."
        case .tooManyFiles(let maximum): return "The skill contains more than the allowed \(maximum) files."
        case .tooManyEntries(let maximum): return "The skill store contains more than the allowed \(maximum) filesystem entries."
        case .enumerationTimedOut: return "The skill store could not be inspected within its bounded deadline."
        case .fileTooLarge(let path): return "A skill file exceeds the allowed size: \(path)."
        case .bundleTooLarge: return "The skill bundle exceeds the allowed total size."
        case .skillLimitReached(let maximum): return "The private store already contains the maximum \(maximum) skills."
        case .policyLimitReached(let maximum): return "The private store already contains the maximum \(maximum) project policies."
        case .invalidProjectIdentity: return "The selected project has an invalid private identifier."
        case .duplicateSkill(let name): return "A skill named \(name) is already installed."
        case .skillNotFound(let name): return "The skill \(name) is not installed."
        case .corruptState: return "The skill trust database is damaged or has an unsupported format."
        case .changedSinceImport(let name): return "The installed files for \(name) changed after review. Re-import the skill before using it."
        case .ioFailure(let operation): return "The private skill store could not complete: \(operation)."
        }
    }
}

enum SkillsTrustPersistenceStage: Equatable, Sendable {
    case beforeWrite
    case beforeRename
}

enum SkillsTrustStateLimits {
    static let maximumDocumentBytes = 8 * 1_024 * 1_024
    static let maximumDescriptionBytes = 4_096
    static let maximumSourceLabelBytes = 512
}

/// Imports skills as inert data. It never invokes a script, shell, package
/// manager, manifest hook, or executable bit from the selected bundle.
final class SkillsTrustStore {
    struct Limits: Equatable {
        var maximumSkills = 128
        var maximumFilesPerSkill = 256
        var maximumBundleBytes: Int64 = 32 * 1_024 * 1_024
        var maximumFileBytes: Int64 = 8 * 1_024 * 1_024
        var maximumSkillMarkdownBytes: Int64 = 1 * 1_024 * 1_024
        var maximumDepth = 12
        var maximumProjectPolicies = 4_096
        var maximumEntriesPerSkill = 4_096
        var maximumCatalogEntries = 32_768
        var enumerationDeadlineSeconds: TimeInterval = 2

        static let production = Limits()
    }

    private struct PersistedState: Codable {
        var version: Int
        var skills: [String: InstalledSkill]
        var policies: [String: SkillProjectPolicy]

        static let empty = PersistedState(version: 1, skills: [:], policies: [:])
    }

    private struct CapturedFile {
        let relativePath: String
        let data: Data
        let hadExecutableBit: Bool
    }

    private struct CapturedBundle {
        let inspection: SkillBundleInspection
        let files: [CapturedFile]
    }

    private struct EnumerationBudget {
        var remainingEntries: Int
        let maximumEntries: Int
        let deadline: UInt64
        let now: () -> UInt64
        let externalCheckpoint: (() throws -> Void)?

        mutating func check() throws {
            try externalCheckpoint?()
            guard now() <= deadline else { throw SkillsTrustStoreError.enumerationTimedOut }
        }

        mutating func consumeEntry() throws {
            try check()
            guard remainingEntries > 0 else {
                throw SkillsTrustStoreError.tooManyEntries(maximumEntries)
            }
            remainingEntries -= 1
        }
    }

    private let fileManager: FileManager
    private let limits: Limits
    private let stateURL: URL
    private let packagesRoot: URL
    let containerRoot: URL
    let runtimeRoot: URL
    private let statePersistenceFailureInjector: ((SkillsTrustPersistenceStage) throws -> Void)?
    private let enumerationNow: () -> UInt64
    private var state: PersistedState

    init(
        applicationSupport: URL,
        harnessHome: URL,
        limits: Limits = .production,
        fileManager: FileManager = .default,
        statePersistenceFailureInjector: ((SkillsTrustPersistenceStage) throws -> Void)? = nil,
        enumerationNow: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    ) throws {
        self.fileManager = fileManager
        self.limits = limits
        containerRoot = harnessHome.appendingPathComponent("skills", isDirectory: true)
        packagesRoot = containerRoot.appendingPathComponent("Packages", isDirectory: true)
        runtimeRoot = containerRoot.appendingPathComponent("Active", isDirectory: true)
        let securityRoot = applicationSupport.appendingPathComponent("Security", isDirectory: true)
        stateURL = securityRoot.appendingPathComponent("skills-trust.json")
        self.statePersistenceFailureInjector = statePersistenceFailureInjector
        self.enumerationNow = enumerationNow
        state = .empty

        try Self.ensurePrivateDirectory(securityRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(containerRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(packagesRoot, fileManager: fileManager)
        try Self.ensurePrivateDirectory(runtimeRoot, fileManager: fileManager)

        if let decoded = try Self.loadState(from: stateURL, limits: limits) {
            state = decoded
        } else {
            try persist(.empty)
        }

        // An activation is intentionally ephemeral. Never carry a local-only
        // project's catalog across an app relaunch or provider-boundary change.
        let emptyStage = containerRoot.appendingPathComponent(".active-\(UUID().uuidString)", isDirectory: true)
        try Self.ensurePrivateDirectory(emptyStage, fileManager: fileManager)
        try replaceDirectory(at: runtimeRoot, with: emptyStage)
    }

    func inspect(at sourceURL: URL) throws -> SkillBundleInspection {
        try captureBundle(at: sourceURL).inspection
    }

    @discardableResult
    func importBundle(at sourceURL: URL, replacingExisting: Bool = false) throws -> InstalledSkill {
        let captured = try captureBundle(at: sourceURL)
        let name = captured.inspection.name
        let existing = state.skills[name]
        if existing != nil, !replacingExisting { throw SkillsTrustStoreError.duplicateSkill(name) }
        if existing == nil, state.skills.count >= limits.maximumSkills {
            throw SkillsTrustStoreError.skillLimitReached(limits.maximumSkills)
        }

        // Packages are quarantine/draft state. Keep the current runtime's
        // reviewed Active snapshot immutable until the lifecycle gate has
        // exact-stopped that runtime and startup materializes a new snapshot.
        let staging = containerRoot.appendingPathComponent(".import-\(UUID().uuidString)", isDirectory: true)
        let destination = packagesRoot.appendingPathComponent(name, isDirectory: true)
        try Self.ensureDescendant(staging, of: containerRoot)
        try Self.ensureDescendant(destination, of: packagesRoot)

        do {
            try write(captured, to: staging)
            let verified = try captureBundle(at: staging).inspection
            guard verified.fingerprint == captured.inspection.fingerprint else {
                throw SkillsTrustStoreError.ioFailure("the copied bundle did not match its reviewed fingerprint")
            }
            try replaceDirectory(at: destination, with: staging)

            let installed = InstalledSkill(
                name: name,
                description: captured.inspection.description,
                fingerprint: captured.inspection.fingerprint,
                sourceLabel: captured.inspection.sourceLabel,
                fileCount: captured.inspection.fileCount,
                totalBytes: captured.inspection.totalBytes,
                riskFlags: captured.inspection.riskFlags,
                importedAt: Date()
            )
            var updated = state
            updated.skills[name] = installed
            if existing?.fingerprint != installed.fingerprint {
                updated.policies = updated.policies.filter { $0.value.skillID != name }
            }
            try persist(updated)
            state = updated
            return installed
        } catch {
            try? fileManager.removeItem(at: staging)
            throw error
        }
    }

    func remove(skillID: String) throws {
        guard state.skills[skillID] != nil else { throw SkillsTrustStoreError.skillNotFound(skillID) }
        let package = packagesRoot.appendingPathComponent(skillID, isDirectory: true)
        try Self.ensureDescendant(package, of: packagesRoot)
        if fileManager.fileExists(atPath: package.path) { try fileManager.removeItem(at: package) }
        var updated = state
        updated.skills.removeValue(forKey: skillID)
        updated.policies = updated.policies.filter { $0.value.skillID != skillID }
        try persist(updated)
        state = updated
    }

    func installedSkills() -> [InstalledSkill] {
        state.skills.values.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    func policy(skillID: String, projectID: String) -> SkillProjectPolicy {
        let key = Self.policyKey(skillID: skillID, projectID: projectID)
        if let policy = state.policies[key],
           policy.approvedFingerprint == state.skills[skillID]?.fingerprint {
            return policy
        }
        return SkillProjectPolicy(
            skillID: skillID,
            projectID: projectID,
            approvedFingerprint: state.skills[skillID]?.fingerprint ?? "",
            enabled: false,
            cloudDisclosure: .localOnly,
            updatedAt: .distantPast
        )
    }

    func setPolicy(
        skillID: String,
        projectID: String,
        enabled: Bool,
        cloudDisclosure: SkillCloudDisclosure
    ) throws {
        guard let installed = state.skills[skillID] else { throw SkillsTrustStoreError.skillNotFound(skillID) }
        guard Self.isValidProjectID(projectID) else { throw SkillsTrustStoreError.invalidProjectIdentity }
        // Policy is draft state for the next runtime boundary. The current
        // process keeps its immutable reviewed Active snapshot; callers apply
        // this edit through the protected lifecycle gate before a new process
        // is exposed.
        let key = Self.policyKey(skillID: skillID, projectID: projectID)
        if state.policies[key] == nil, state.policies.count >= limits.maximumProjectPolicies {
            throw SkillsTrustStoreError.policyLimitReached(limits.maximumProjectPolicies)
        }
        var updated = state
        updated.policies[key] = SkillProjectPolicy(
            skillID: skillID,
            projectID: projectID,
            approvedFingerprint: installed.fingerprint,
            enabled: enabled,
            cloudDisclosure: cloudDisclosure,
            updatedAt: Date()
        )
        try persist(updated)
        state = updated
    }

    func activationPlan(
        projectID: String,
        boundary: SkillExecutionBoundary,
        oneTimeCloudApprovals: Set<String> = []
    ) -> SkillActivationPlan {
        var included: [InstalledSkill] = []
        var needsConsent: [InstalledSkill] = []
        var withheld: [InstalledSkill] = []

        for skill in installedSkills() {
            let current = policy(skillID: skill.id, projectID: projectID)
            guard current.enabled else { continue }
            if boundary == .local {
                included.append(skill)
                continue
            }
            switch current.cloudDisclosure {
            case .allowed:
                included.append(skill)
            case .askEveryTime where oneTimeCloudApprovals.contains(skill.id):
                included.append(skill)
            case .askEveryTime:
                needsConsent.append(skill)
            case .localOnly:
                withheld.append(skill)
            }
        }
        return SkillActivationPlan(
            projectID: projectID,
            boundary: boundary,
            included: included,
            needsCloudConsent: needsConsent,
            withheld: withheld
        )
    }

    /// Materializes only the reviewed skills permitted for the active project
    /// and provider boundary. The DSH scanner is configured to see this
    /// directory, never the package quarantine or arbitrary project roots.
    @discardableResult
    func activate(
        projectID: String,
        boundary: SkillExecutionBoundary,
        oneTimeCloudApprovals: Set<String> = [],
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> SkillActivationResult {
        try preparationBudget?.checkpoint()
        let plan = activationPlan(
            projectID: projectID,
            boundary: boundary,
            oneTimeCloudApprovals: oneTimeCloudApprovals
        )
        let stage = containerRoot.appendingPathComponent(".active-\(UUID().uuidString)", isDirectory: true)
        try Self.ensurePrivateDirectory(stage, fileManager: fileManager)
        do {
            for skill in plan.included {
                try preparationBudget?.checkpoint()
                let source = packagesRoot.appendingPathComponent(skill.id, isDirectory: true)
                let captured = try captureBundle(at: source, preparationBudget: preparationBudget)
                guard captured.inspection.fingerprint == skill.fingerprint else {
                    throw SkillsTrustStoreError.changedSinceImport(skill.id)
                }
                try write(
                    captured,
                    to: stage.appendingPathComponent(skill.id, isDirectory: true),
                    preparationBudget: preparationBudget
                )
            }
            try preparationBudget?.checkpoint()
            try replaceDirectory(at: runtimeRoot, with: stage)
        } catch {
            try? fileManager.removeItem(at: stage)
            try? deactivateAll()
            throw error
        }
        return SkillActivationResult(
            projectID: projectID,
            boundary: boundary,
            activeSkills: plan.included,
            runtimeRoot: runtimeRoot
        )
    }

    func audit() -> [SkillTrustFinding] {
        var findings: [SkillTrustFinding] = []
        var budget = makeEnumerationBudget(maximumEntries: limits.maximumCatalogEntries)
        for skill in installedSkills() {
            let url = packagesRoot.appendingPathComponent(skill.id, isDirectory: true)
            guard fileManager.fileExists(atPath: url.path) else {
                findings.append(SkillTrustFinding(
                    id: skill.id,
                    status: .missing,
                    expectedFingerprint: skill.fingerprint,
                    observedFingerprint: nil,
                    detail: "The reviewed package is missing."
                ))
                continue
            }
            do {
                let observed = try captureBundle(at: url, budget: &budget).inspection.fingerprint
                findings.append(SkillTrustFinding(
                    id: skill.id,
                    status: observed == skill.fingerprint ? .trusted : .modified,
                    expectedFingerprint: skill.fingerprint,
                    observedFingerprint: observed,
                    detail: observed == skill.fingerprint ? "Fingerprint verified." : "Files changed after import."
                ))
            } catch {
                findings.append(SkillTrustFinding(
                    id: skill.id,
                    status: .invalid,
                    expectedFingerprint: skill.fingerprint,
                    observedFingerprint: nil,
                    detail: error.localizedDescription
                ))
            }
        }

        do {
            let entries = try boundedDirectoryEntries(at: packagesRoot, budget: &budget)
            for entry in entries where state.skills[entry.lastPathComponent] == nil {
                findings.append(SkillTrustFinding(
                    id: entry.lastPathComponent,
                    status: .unexpected,
                    expectedFingerprint: nil,
                    observedFingerprint: nil,
                    detail: "An unregistered package is present in the private store."
                ))
            }
        } catch {
            findings.append(SkillTrustFinding(
                id: "skill-store-catalog",
                status: .invalid,
                expectedFingerprint: nil,
                observedFingerprint: nil,
                detail: error.localizedDescription
            ))
        }
        return findings.sorted { $0.id < $1.id }
    }

    func validateActiveCatalog(
        against result: SkillActivationResult,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws {
        try preparationBudget?.checkpoint()
        let expected = Dictionary(uniqueKeysWithValues: result.activeSkills.map { ($0.id, $0.fingerprint) })
        var budget = makeEnumerationBudget(
            maximumEntries: limits.maximumCatalogEntries,
            preparationBudget: preparationBudget
        )
        let entries = try boundedDirectoryEntries(at: runtimeRoot, budget: &budget)
        guard Set(entries.map(\.lastPathComponent)) == Set(expected.keys) else {
            throw SkillsTrustStoreError.changedSinceImport("active skill catalog")
        }
        for entry in entries {
            let observed = try captureBundle(at: entry, budget: &budget).inspection.fingerprint
            guard observed == expected[entry.lastPathComponent] else {
                throw SkillsTrustStoreError.changedSinceImport(entry.lastPathComponent)
            }
        }
    }

    func deactivateAll() throws {
        let empty = containerRoot.appendingPathComponent(".active-\(UUID().uuidString)", isDirectory: true)
        try Self.ensurePrivateDirectory(empty, fileManager: fileManager)
        do {
            try replaceDirectory(at: runtimeRoot, with: empty)
        } catch {
            try? fileManager.removeItem(at: empty)
            throw error
        }
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func captureBundle(
        at originalURL: URL,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws -> CapturedBundle {
        var budget = makeEnumerationBudget(
            maximumEntries: limits.maximumEntriesPerSkill,
            preparationBudget: preparationBudget
        )
        return try captureBundle(at: originalURL, budget: &budget)
    }

    private func captureBundle(
        at originalURL: URL,
        budget: inout EnumerationBudget
    ) throws -> CapturedBundle {
        let sourceURL: URL
        let rootValues = try lstatValues(originalURL)
        if rootValues.kind == .symbolicLink { throw SkillsTrustStoreError.symbolicLink(originalURL.path) }
        if rootValues.kind == .regularFile {
            guard originalURL.lastPathComponent == "SKILL.md" else {
                throw SkillsTrustStoreError.invalidBundle("select a directory bundle or its SKILL.md")
            }
            sourceURL = originalURL.deletingLastPathComponent()
        } else if rootValues.kind == .directory {
            sourceURL = originalURL
        } else {
            throw SkillsTrustStoreError.unsupportedEntry(originalURL.path)
        }

        let sourceValues = try lstatValues(sourceURL)
        guard sourceValues.kind == .directory else { throw SkillsTrustStoreError.invalidBundle(sourceURL.path) }
        let canonicalRoot = sourceURL.standardizedFileURL.resolvingSymlinksInPath()
        guard canonicalRoot.path == sourceURL.standardizedFileURL.path else {
            throw SkillsTrustStoreError.symbolicLink(sourceURL.path)
        }

        var files: [CapturedFile] = []
        var totalBytes: Int64 = 0
        try collectFiles(
            at: sourceURL,
            root: canonicalRoot,
            relativePrefix: "",
            depth: 0,
            files: &files,
            totalBytes: &totalBytes,
            budget: &budget
        )
        files.sort { $0.relativePath < $1.relativePath }
        guard let skillFile = files.first(where: { $0.relativePath == "SKILL.md" }) else {
            throw SkillsTrustStoreError.invalidBundle("SKILL.md is missing from the selected directory")
        }
        guard Int64(skillFile.data.count) <= limits.maximumSkillMarkdownBytes else {
            throw SkillsTrustStoreError.fileTooLarge("SKILL.md")
        }
        guard let markdown = String(data: skillFile.data, encoding: .utf8) else {
            throw SkillsTrustStoreError.invalidBundle("SKILL.md must be UTF-8 text")
        }
        let metadata = try Self.parseFrontmatter(markdown)

        var hasher = SHA256()
        hasher.update(data: Data("local-harness-skill-v1\u{0}".utf8))
        var riskFlags = Set<SkillRiskFlag>()
        for file in files {
            Self.hashLengthPrefixed(Data(file.relativePath.utf8), into: &hasher)
            Self.hashLengthPrefixed(file.data, into: &hasher)
            if file.hadExecutableBit { riskFlags.insert(.containsExecutableFile) }
            if Self.isScriptPath(file.relativePath) { riskFlags.insert(.containsScript) }
            if file.relativePath != "SKILL.md", String(data: file.data, encoding: .utf8) == nil {
                riskFlags.insert(.containsBinaryResource)
            }
        }
        let fingerprint = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        let inspection = SkillBundleInspection(
            name: metadata.name,
            description: metadata.description,
            fingerprint: fingerprint,
            sourceLabel: Self.safeSourceLabel(sourceURL.lastPathComponent),
            fileCount: files.count,
            totalBytes: totalBytes,
            riskFlags: riskFlags.sorted { $0.rawValue < $1.rawValue }
        )
        return CapturedBundle(inspection: inspection, files: files)
    }

    private enum FileKind { case regularFile, directory, symbolicLink, other }
    private struct FileValues { let kind: FileKind; let size: Int64; let permissions: mode_t }

    private func lstatValues(_ url: URL) throws -> FileValues {
        var value = stat()
        guard Darwin.lstat(url.path, &value) == 0 else {
            throw SkillsTrustStoreError.ioFailure("read \(url.lastPathComponent)")
        }
        let type = value.st_mode & S_IFMT
        let kind: FileKind
        switch type {
        case S_IFREG: kind = .regularFile
        case S_IFDIR: kind = .directory
        case S_IFLNK: kind = .symbolicLink
        default: kind = .other
        }
        return FileValues(kind: kind, size: Int64(value.st_size), permissions: value.st_mode)
    }

    private func collectFiles(
        at directory: URL,
        root: URL,
        relativePrefix: String,
        depth: Int,
        files: inout [CapturedFile],
        totalBytes: inout Int64,
        budget: inout EnumerationBudget
    ) throws {
        guard depth <= limits.maximumDepth else {
            throw SkillsTrustStoreError.invalidBundle("directory nesting exceeds \(limits.maximumDepth) levels")
        }
        let resolved = directory.standardizedFileURL.resolvingSymlinksInPath()
        try Self.ensureDescendantOrEqual(resolved, of: root)
        let entries = try boundedDirectoryEntries(at: directory, budget: &budget)

        for entry in entries {
            let name = entry.lastPathComponent
            guard Self.isSafePathComponent(name) else {
                throw SkillsTrustStoreError.invalidBundle("unsafe path component \(name)")
            }
            let relative = relativePrefix.isEmpty ? name : "\(relativePrefix)/\(name)"
            guard relative.utf8.count <= 1_024 else { throw SkillsTrustStoreError.invalidBundle("path is too long") }
            let values = try lstatValues(entry)
            switch values.kind {
            case .symbolicLink:
                throw SkillsTrustStoreError.symbolicLink(relative)
            case .directory:
                let childResolved = entry.standardizedFileURL.resolvingSymlinksInPath()
                try Self.ensureDescendantOrEqual(childResolved, of: root)
                try collectFiles(
                    at: entry,
                    root: root,
                    relativePrefix: relative,
                    depth: depth + 1,
                    files: &files,
                    totalBytes: &totalBytes,
                    budget: &budget
                )
            case .regularFile:
                guard files.count < limits.maximumFilesPerSkill else {
                    throw SkillsTrustStoreError.tooManyFiles(limits.maximumFilesPerSkill)
                }
                let limit = relative == "SKILL.md"
                    ? min(limits.maximumFileBytes, limits.maximumSkillMarkdownBytes)
                    : limits.maximumFileBytes
                guard values.size <= limit else { throw SkillsTrustStoreError.fileTooLarge(relative) }
                let data = try readRegularFileNoFollow(entry, maximumBytes: limit)
                totalBytes += Int64(data.count)
                guard totalBytes <= limits.maximumBundleBytes else { throw SkillsTrustStoreError.bundleTooLarge }
                files.append(CapturedFile(
                    relativePath: relative,
                    data: data,
                    hadExecutableBit: values.permissions & 0o111 != 0
                ))
            case .other:
                throw SkillsTrustStoreError.unsupportedEntry(relative)
            }
        }
    }

    private func readRegularFileNoFollow(_ url: URL, maximumBytes: Int64) throws -> Data {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ELOOP { throw SkillsTrustStoreError.symbolicLink(url.path) }
            throw SkillsTrustStoreError.ioFailure("open \(url.lastPathComponent)")
        }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG else {
            throw SkillsTrustStoreError.unsupportedEntry(url.path)
        }
        guard Int64(metadata.st_size) <= maximumBytes else {
            throw SkillsTrustStoreError.fileTooLarge(url.lastPathComponent)
        }

        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw SkillsTrustStoreError.ioFailure("read \(url.lastPathComponent)")
            }
            guard Int64(result.count + count) <= maximumBytes else {
                throw SkillsTrustStoreError.fileTooLarge(url.lastPathComponent)
            }
            result.append(contentsOf: buffer.prefix(count))
        }
        return result
    }

    private func makeEnumerationBudget(
        maximumEntries: Int,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) -> EnumerationBudget {
        let boundedMaximum = max(0, maximumEntries)
        let start = enumerationNow()
        let configuredSeconds = limits.enumerationDeadlineSeconds
        let boundedSeconds = configuredSeconds.isFinite
            ? max(0, min(configuredSeconds, 30))
            : 0
        let delta = UInt64(boundedSeconds * 1_000_000_000)
        let addition = start.addingReportingOverflow(delta)
        return EnumerationBudget(
            remainingEntries: boundedMaximum,
            maximumEntries: boundedMaximum,
            deadline: addition.overflow ? UInt64.max : addition.partialValue,
            now: enumerationNow,
            externalCheckpoint: preparationBudget.map { budget in
                { try budget.checkpoint() }
            }
        )
    }

    /// Streams one local directory through a no-follow descriptor. The entry
    /// and monotonic time budgets are charged before an entry is retained, so
    /// an empty-directory flood cannot force whole-directory allocation.
    private func boundedDirectoryEntries(
        at directory: URL,
        budget: inout EnumerationBudget
    ) throws -> [URL] {
        try budget.check()
        let descriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
            if errno == ELOOP { throw SkillsTrustStoreError.symbolicLink(directory.path) }
            throw SkillsTrustStoreError.ioFailure("open \(directory.lastPathComponent)")
        }
        guard let stream = fdopendir(descriptor) else {
            _ = Darwin.close(descriptor)
            throw SkillsTrustStoreError.ioFailure("enumerate \(directory.lastPathComponent)")
        }
        defer { _ = closedir(stream) }

        var entries: [URL] = []
        while true {
            try budget.check()
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else {
                    throw SkillsTrustStoreError.ioFailure("enumerate \(directory.lastPathComponent)")
                }
                break
            }
            guard let name = DarwinDirectoryEntry.name(entry) else {
                throw SkillsTrustStoreError.invalidBundle("a directory entry is not valid UTF-8")
            }
            if name == "." || name == ".." { continue }
            try budget.consumeEntry()
            entries.append(directory.appendingPathComponent(name))
        }
        return entries.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func write(
        _ captured: CapturedBundle,
        to destination: URL,
        preparationBudget: RuntimeStartupPrerequisiteBudget? = nil
    ) throws {
        try preparationBudget?.checkpoint()
        try Self.ensurePrivateDirectory(destination, fileManager: fileManager)
        for file in captured.files {
            try preparationBudget?.checkpoint()
            var parent = destination
            for component in file.relativePath.split(separator: "/").dropLast() {
                parent.appendPathComponent(String(component), isDirectory: true)
                try Self.ensurePrivateDirectory(parent, fileManager: fileManager)
            }
            let target = destination.appendingPathComponent(file.relativePath)
            try Self.ensureDescendant(target, of: destination)
            try file.data.write(to: target, options: [.atomic])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        }
        try preparationBudget?.checkpoint()
    }

    private func replaceDirectory(at destination: URL, with staged: URL) throws {
        let backup = containerRoot.appendingPathComponent(".backup-\(UUID().uuidString)", isDirectory: true)
        let hadDestination = fileManager.fileExists(atPath: destination.path)
        do {
            if hadDestination { try fileManager.moveItem(at: destination, to: backup) }
            try fileManager.moveItem(at: staged, to: destination)
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: destination.path)
            if hadDestination { try? fileManager.removeItem(at: backup) }
        } catch {
            if !fileManager.fileExists(atPath: destination.path), fileManager.fileExists(atPath: backup.path) {
                try? fileManager.moveItem(at: backup, to: destination)
            }
            throw error
        }
    }

    private static func loadState(
        from stateURL: URL,
        limits: Limits
    ) throws -> PersistedState? {
        let descriptor = Darwin.open(
            stateURL.path,
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw SkillsTrustStoreError.corruptState
        }
        defer { _ = Darwin.close(descriptor) }

        var before = stat()
        guard fstat(descriptor, &before) == 0,
              isPrivateStateDocument(before),
              before.st_size >= 0,
              UInt64(before.st_size) <= UInt64(SkillsTrustStateLimits.maximumDocumentBytes)
        else {
            throw SkillsTrustStoreError.corruptState
        }

        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
        while data.count <= SkillsTrustStateLimits.maximumDocumentBytes {
            let remaining = SkillsTrustStateLimits.maximumDocumentBytes + 1 - data.count
            let requested = min(buffer.count, remaining)
            let count = Darwin.read(descriptor, &buffer, requested)
            if count > 0 {
                data.append(contentsOf: buffer.prefix(count))
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            throw SkillsTrustStoreError.corruptState
        }
        guard !data.isEmpty,
              data.count <= SkillsTrustStateLimits.maximumDocumentBytes
        else {
            throw SkillsTrustStoreError.corruptState
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              isPrivateStateDocument(after),
              after.st_dev == before.st_dev,
              after.st_ino == before.st_ino,
              after.st_size == before.st_size,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec
        else {
            throw SkillsTrustStoreError.corruptState
        }

        guard hasStrictStateSchema(data, limits: limits),
              let decoded = try? JSONDecoder().decode(PersistedState.self, from: data),
              isValid(decoded, limits: limits) else {
            throw SkillsTrustStoreError.corruptState
        }
        return decoded
    }

    private func persist(_ candidate: PersistedState) throws {
        guard Self.isValid(candidate, limits: limits) else {
            throw SkillsTrustStoreError.corruptState
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(candidate)
        guard data.count <= SkillsTrustStateLimits.maximumDocumentBytes else {
            throw SkillsTrustStoreError.corruptState
        }
        try Self.atomicPrivateStateWrite(
            data,
            to: stateURL,
            failureInjector: statePersistenceFailureInjector
        )
    }

    private static func atomicPrivateStateWrite(
        _ data: Data,
        to stateURL: URL,
        failureInjector: ((SkillsTrustPersistenceStage) throws -> Void)?
    ) throws {
        let directory = stateURL.deletingLastPathComponent()
        let directoryDescriptor = Darwin.open(
            directory.path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            throw SkillsTrustStoreError.unsafeStorage(directory.path)
        }
        defer { _ = Darwin.close(directoryDescriptor) }
        var directoryMetadata = stat()
        guard fstat(directoryDescriptor, &directoryMetadata) == 0,
              (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
              directoryMetadata.st_uid == geteuid(),
              (directoryMetadata.st_mode & mode_t(0o7777)) == mode_t(0o700)
        else {
            throw SkillsTrustStoreError.unsafeStorage(directory.path)
        }
        try requireSafeStateDestinationIfPresent(
            directoryDescriptor: directoryDescriptor,
            filename: stateURL.lastPathComponent,
            path: stateURL.path
        )

        let temporaryName = ".skills-trust.\(UUID().uuidString).tmp"
        let descriptor = temporaryName.withCString { name in
            openat(
                directoryDescriptor,
                name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else {
            throw SkillsTrustStoreError.ioFailure("save skill trust state")
        }
        var descriptorOpen = true
        var temporaryExists = true
        defer {
            if descriptorOpen { _ = Darwin.close(descriptor) }
            if temporaryExists {
                temporaryName.withCString { name in _ = unlinkat(directoryDescriptor, name, 0) }
            }
        }

        do {
            try failureInjector?(.beforeWrite)
            try writeAllStateBytes(data, descriptor: descriptor)
            guard fsync(descriptor) == 0 else {
                throw SkillsTrustStoreError.ioFailure("sync skill trust state")
            }
            let closeResult = Darwin.close(descriptor)
            descriptorOpen = false
            guard closeResult == 0 else {
                throw SkillsTrustStoreError.ioFailure("close skill trust state")
            }

            try failureInjector?(.beforeRename)
            try requireSafeStateDestinationIfPresent(
                directoryDescriptor: directoryDescriptor,
                filename: stateURL.lastPathComponent,
                path: stateURL.path
            )
            let renamed = temporaryName.withCString { temporary in
                stateURL.lastPathComponent.withCString { destination in
                    renameat(directoryDescriptor, temporary, directoryDescriptor, destination)
                }
            }
            guard renamed == 0 else {
                throw SkillsTrustStoreError.ioFailure("replace skill trust state")
            }
            temporaryExists = false

            var persisted = stat()
            let inspected = stateURL.lastPathComponent.withCString { name in
                fstatat(directoryDescriptor, name, &persisted, AT_SYMLINK_NOFOLLOW)
            }
            guard inspected == 0, isPrivateStateDocument(persisted) else {
                throw SkillsTrustStoreError.ioFailure("verify skill trust state")
            }
            guard fsync(directoryDescriptor) == 0 else {
                throw SkillsTrustStoreError.ioFailure("sync skill trust directory")
            }
        } catch let error as SkillsTrustStoreError {
            throw error
        } catch {
            throw SkillsTrustStoreError.ioFailure("save skill trust state")
        }
    }

    private static func requireSafeStateDestinationIfPresent(
        directoryDescriptor: Int32,
        filename: String,
        path: String
    ) throws {
        var metadata = stat()
        let result = filename.withCString { name in
            fstatat(directoryDescriptor, name, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0 {
            if errno == ENOENT { return }
            throw SkillsTrustStoreError.unsafeStorage(path)
        }
        guard isPrivateStateDocument(metadata) else {
            throw SkillsTrustStoreError.unsafeStorage(path)
        }
    }

    private static func writeAllStateBytes(_ data: Data, descriptor: Int32) throws {
        var writeFailed = false
        data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    writeFailed = true
                    break
                }
            }
        }
        if writeFailed { throw SkillsTrustStoreError.ioFailure("write skill trust state") }
    }

    private static func isPrivateStateDocument(_ metadata: stat) -> Bool {
        (metadata.st_mode & S_IFMT) == S_IFREG &&
            metadata.st_uid == geteuid() &&
            metadata.st_nlink == 1 &&
            (metadata.st_mode & mode_t(0o7777)) == mode_t(0o600)
    }

    private static func hasStrictStateSchema(_ data: Data, limits: Limits) -> Bool {
        guard let document = try? JSONSerialization.jsonObject(with: data),
              let object = document as? [String: Any],
              Set(object.keys) == Set(["version", "skills", "policies"]),
              let version = object["version"] as? Int,
              version == 1,
              let skills = object["skills"] as? [String: Any],
              let policies = object["policies"] as? [String: Any],
              skills.count <= limits.maximumSkills,
              policies.count <= limits.maximumProjectPolicies else {
            return false
        }
        let skillKeys = Set([
            "name", "description", "fingerprint", "sourceLabel", "fileCount",
            "totalBytes", "riskFlags", "importedAt"
        ])
        let policyKeys = Set([
            "skillID", "projectID", "approvedFingerprint", "enabled",
            "cloudDisclosure", "updatedAt"
        ])
        return skills.values.allSatisfy { value in
            guard let record = value as? [String: Any] else { return false }
            return Set(record.keys) == skillKeys
        } && policies.values.allSatisfy { value in
            guard let record = value as? [String: Any] else { return false }
            return Set(record.keys) == policyKeys
        }
    }

    private static func ensurePrivateDirectory(_ url: URL, fileManager: FileManager) throws {
        if fileManager.fileExists(atPath: url.path) {
            guard !isSymbolicLink(url) else { throw SkillsTrustStoreError.unsafeStorage(url.path) }
            var metadata = stat()
            guard Darwin.lstat(url.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
                throw SkillsTrustStoreError.unsafeStorage(url.path)
            }
        } else {
            try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private static func isSymbolicLink(_ url: URL) -> Bool {
        var metadata = stat()
        return Darwin.lstat(url.path, &metadata) == 0 && metadata.st_mode & S_IFMT == S_IFLNK
    }

    private static func ensureDescendant(_ candidate: URL, of root: URL) throws {
        let child = candidate.standardizedFileURL.path
        let parent = root.standardizedFileURL.path
        guard child.hasPrefix(parent + "/") else { throw SkillsTrustStoreError.pathEscape(candidate.path) }
    }

    private static func ensureDescendantOrEqual(_ candidate: URL, of root: URL) throws {
        let child = candidate.standardizedFileURL.path
        let parent = root.standardizedFileURL.path
        guard child == parent || child.hasPrefix(parent + "/") else {
            throw SkillsTrustStoreError.pathEscape(candidate.path)
        }
    }

    private static func isSafePathComponent(_ name: String) -> Bool {
        guard !name.isEmpty, name != ".", name != "..", !name.hasPrefix("."), name.utf8.count <= 255 else { return false }
        return name.rangeOfCharacter(from: .controlCharacters) == nil && !name.contains("/") && !name.contains(":")
    }

    private static func policyKey(skillID: String, projectID: String) -> String {
        "\(projectID)\u{0}\(skillID)"
    }

    private static func isValid(_ state: PersistedState, limits: Limits) -> Bool {
        guard state.version == 1,
              state.skills.count <= limits.maximumSkills,
              state.policies.count <= limits.maximumProjectPolicies else { return false }
        for (key, skill) in state.skills {
            guard key == skill.name, isValidSkillName(skill.name),
                  !skill.description.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  skill.description.utf8.count <= SkillsTrustStateLimits.maximumDescriptionBytes,
                  skill.fingerprint.range(of: #"^[a-f0-9]{64}$"#, options: .regularExpression) != nil,
                  !skill.sourceLabel.isEmpty,
                  skill.sourceLabel.utf8.count <= SkillsTrustStateLimits.maximumSourceLabelBytes,
                  skill.sourceLabel.rangeOfCharacter(from: .controlCharacters) == nil,
                  skill.fileCount > 0, skill.fileCount <= limits.maximumFilesPerSkill,
                  skill.totalBytes >= 0, skill.totalBytes <= limits.maximumBundleBytes,
                  Set(skill.riskFlags).count == skill.riskFlags.count,
                  skill.riskFlags.count <= SkillRiskFlag.allCases.count,
                  skill.importedAt.timeIntervalSinceReferenceDate.isFinite else { return false }
        }
        for (key, policy) in state.policies {
            guard key == policyKey(skillID: policy.skillID, projectID: policy.projectID),
                  isValidSkillName(policy.skillID),
                  isValidProjectID(policy.projectID),
                  state.skills[policy.skillID]?.fingerprint == policy.approvedFingerprint,
                  policy.approvedFingerprint.range(
                    of: #"^[a-f0-9]{64}$"#,
                    options: .regularExpression
                  ) != nil,
                  policy.updatedAt.timeIntervalSinceReferenceDate.isFinite else { return false }
        }
        return true
    }

    private static func isValidProjectID(_ value: String) -> Bool {
        value.range(of: #"^[A-Za-z0-9._-]{1,128}$"#, options: .regularExpression) != nil
    }

    private static func isValidSkillName(_ value: String) -> Bool {
        value.range(of: #"^[a-z0-9]+(?:-[a-z0-9]+)*$"#, options: .regularExpression) != nil && value.utf8.count <= 96
    }

    private static func safeSourceLabel(_ value: String) -> String {
        let label = value.components(separatedBy: .controlCharacters).joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !label.isEmpty else { return "Imported skill" }
        return String(label.prefix(128))
    }

    private static func isScriptPath(_ path: String) -> Bool {
        let scriptExtensions: Set<String> = [
            "sh", "bash", "zsh", "command", "py", "rb", "pl", "php",
            "js", "mjs", "cjs", "ts", "tsx", "swift", "lua", "ps1"
        ]
        return scriptExtensions.contains((path as NSString).pathExtension.lowercased())
    }

    private static func hashLengthPrefixed(_ data: Data, into hasher: inout SHA256) {
        var length = UInt64(data.count).bigEndian
        withUnsafeBytes(of: &length) { hasher.update(bufferPointer: $0) }
        hasher.update(data: data)
    }

    private static func parseFrontmatter(_ markdown: String) throws -> (name: String, description: String) {
        let normalized = markdown.hasPrefix("\u{FEFF}") ? String(markdown.dropFirst()) : markdown
        let lines = normalized.components(separatedBy: .newlines)
        guard lines.first?.trimmingCharacters(in: .whitespaces) == "---" else {
            throw SkillsTrustStoreError.invalidBundle("SKILL.md must start with YAML frontmatter")
        }
        guard let end = lines.indices.dropFirst().first(where: {
            let line = lines[$0].trimmingCharacters(in: .whitespaces)
            return line == "---" || line == "..."
        }), end <= 512 else {
            throw SkillsTrustStoreError.invalidBundle("SKILL.md frontmatter is missing its closing delimiter or is too large")
        }

        var values: [String: String] = [:]
        var index = 1
        while index < end {
            let line = lines[index]
            if line.trimmingCharacters(in: .whitespaces).isEmpty || line.trimmingCharacters(in: .whitespaces).hasPrefix("#") {
                index += 1
                continue
            }
            guard !line.hasPrefix(" "), !line.hasPrefix("\t"), let separator = line.firstIndex(of: ":") else {
                index += 1
                continue
            }
            let key = line[..<separator].trimmingCharacters(in: .whitespaces)
            var value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { throw SkillsTrustStoreError.invalidBundle("frontmatter contains an empty key") }
            if ["disableModelInvocation", "modelInvocable", "userInvocable"].contains(key) {
                throw SkillsTrustStoreError.invalidBundle("frontmatter uses unsupported legacy invocation field \(key)")
            }
            if key == "disable-model-invocation" || key == "user-invocable" {
                guard isSupportedBooleanScalar(String(value)) else {
                    throw SkillsTrustStoreError.invalidBundle("frontmatter field \(key) must be a boolean")
                }
            }
            if key == "name" || key == "description" {
                guard values[key] == nil else { throw SkillsTrustStoreError.invalidBundle("frontmatter repeats \(key)") }
                if value == "|" || value == ">" || value.hasPrefix("|-") || value.hasPrefix(">-") {
                    var block: [String] = []
                    index += 1
                    while index < end {
                        let blockLine = lines[index]
                        guard blockLine.hasPrefix(" ") else { break }
                        block.append(blockLine.trimmingCharacters(in: .whitespaces))
                        index += 1
                    }
                    values[key] = block.joined(separator: value.hasPrefix(">") ? " " : "\n")
                    continue
                }
                guard !value.hasPrefix("!"), !value.hasPrefix("&"), !value.hasPrefix("*") else {
                    throw SkillsTrustStoreError.invalidBundle("frontmatter uses an unsupported YAML tag or alias")
                }
                guard isStringScalar(String(value)) else {
                    throw SkillsTrustStoreError.invalidBundle("frontmatter field \(key) must be text")
                }
                value = decodeConservativeScalar(String(value))
                values[key] = value
            }
            index += 1
        }

        guard let name = values["name"], isValidSkillName(name) else {
            throw SkillsTrustStoreError.invalidBundle("frontmatter name must be kebab-case and at most 96 bytes")
        }
        guard let description = values["description"]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !description.isEmpty,
              description.utf8.count <= 4_096 else {
            throw SkillsTrustStoreError.invalidBundle("frontmatter description is required and must be at most 4096 bytes")
        }
        return (name, description)
    }

    private static func decodeConservativeScalar(_ input: String) -> String {
        guard input.count >= 2 else { return input }
        if input.hasPrefix("'"), input.hasSuffix("'") {
            return String(input.dropFirst().dropLast()).replacingOccurrences(of: "''", with: "'")
        }
        if input.hasPrefix("\""), input.hasSuffix("\"") {
            let body = String(input.dropFirst().dropLast())
            return body
                .replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\n", with: "\n")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        if let comment = input.range(of: " #") {
            return String(input[..<comment.lowerBound])
        }
        return input
    }

    private static func isStringScalar(_ value: String) -> Bool {
        if value.hasPrefix("\"") { return value.count >= 2 && value.hasSuffix("\"") }
        if value.hasPrefix("'") { return value.count >= 2 && value.hasSuffix("'") }
        let lowered = value.lowercased()
        if ["true", "false", "null", "~", ".nan", ".inf", "-.inf", "+.inf"].contains(lowered) { return false }
        if value.hasPrefix("[") || value.hasPrefix("{") { return false }
        return value.range(
            of: #"^[+-]?[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9]+)?$"#,
            options: .regularExpression
        ) == nil
    }

    private static func isSupportedBooleanScalar(_ value: String) -> Bool {
        let decoded = decodeConservativeScalar(value).lowercased()
        return ["true", "false", "yes", "no", "on", "off", "1", "0"].contains(decoded)
    }
}
