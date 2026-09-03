import Foundation

enum SkillRiskFlag: String, Codable, CaseIterable, Equatable, Hashable {
    case containsExecutableFile
    case containsScript
    case containsBinaryResource
}

struct SkillBundleInspection: Equatable {
    let name: String
    let description: String
    let fingerprint: String
    let sourceLabel: String
    let fileCount: Int
    let totalBytes: Int64
    let riskFlags: [SkillRiskFlag]
}

struct InstalledSkill: Codable, Equatable, Identifiable {
    var id: String { name }

    let name: String
    let description: String
    let fingerprint: String
    let sourceLabel: String
    let fileCount: Int
    let totalBytes: Int64
    let riskFlags: [SkillRiskFlag]
    let importedAt: Date
}

enum SkillCloudDisclosure: String, Codable, CaseIterable, Equatable {
    /// Never place this skill in a catalog used by a non-local model.
    case localOnly
    /// Require a fresh, one-turn authorization before exposing the skill.
    case askEveryTime
    /// Permit disclosure while the installed fingerprint remains unchanged.
    case allowed
}

struct SkillProjectPolicy: Codable, Equatable {
    let skillID: String
    let projectID: String
    let approvedFingerprint: String
    var enabled: Bool
    var cloudDisclosure: SkillCloudDisclosure
    var updatedAt: Date
}

enum SkillExecutionBoundary: String, Codable, Equatable {
    case local
    case external
}

struct SkillActivationPlan: Equatable {
    let projectID: String
    let boundary: SkillExecutionBoundary
    let included: [InstalledSkill]
    let needsCloudConsent: [InstalledSkill]
    let withheld: [InstalledSkill]
}

struct SkillActivationResult: Equatable {
    let projectID: String
    let boundary: SkillExecutionBoundary
    let activeSkills: [InstalledSkill]
    let runtimeRoot: URL
}

struct SkillTrustFinding: Equatable, Identifiable {
    enum Status: String, Equatable {
        case trusted
        case modified
        case missing
        case invalid
        case unexpected
    }

    let id: String
    let status: Status
    let expectedFingerprint: String?
    let observedFingerprint: String?
    let detail: String
}

enum SkillsProjectIdentity {
    /// Produces a stable opaque identifier without persisting the user's path.
    static func identifier(for projectURL: URL) -> String {
        let normalized = projectURL.standardizedFileURL.resolvingSymlinksInPath().path
        return SkillsFingerprint.sha256(Data(normalized.utf8))
    }
}

enum SkillsFingerprint {
    static func sha256(_ data: Data) -> String {
        // Implemented in SkillsTrustStore.swift so the public models do not
        // expose CryptoKit types in their API.
        SkillsTrustStore.sha256(data)
    }
}
