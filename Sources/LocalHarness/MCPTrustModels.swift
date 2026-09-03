import Foundation

/// The only MCP transport Local Harness is prepared to activate. Keeping this
/// type single-case makes accepting a network transport an explicit future
/// security decision instead of a permissive string comparison.
enum MCPTransport: String, Codable, Sendable {
    case stdio
}

enum MCPDisclosureDataKind: String, Codable, CaseIterable, Hashable, Sendable {
    case accountData
    case authenticationMetadata
    case fileContents
    case fileNames
    case projectMetadata
    case toolArguments
    case toolResults
}

/// What the MCP process itself may disclose, independently of the selected
/// model provider. A cloud/local-network process must have a human-readable
/// destination so consent never degrades to a generic "internet" toggle.
struct MCPDisclosureProfile: Codable, Equatable, Sendable {
    let boundary: DataBoundary
    let destinationName: String?
    let dataKinds: [MCPDisclosureDataKind]

    init(
        boundary: DataBoundary,
        destinationName: String? = nil,
        dataKinds: [MCPDisclosureDataKind]
    ) {
        self.boundary = boundary
        self.destinationName = destinationName
        self.dataKinds = dataKinds
    }
}

/// Exact model-provider boundary on which a reviewed MCP server may be used.
/// Provider identifiers remain opaque because DSH owns their vocabulary.
struct MCPProviderEnablement: Codable, Equatable, Hashable, Sendable {
    let provider: ProviderID
    let boundary: DataBoundary
}

/// A credential is named, never serialized. The eventual activation adapter
/// must resolve the reference at launch and pass the value through a one-way
/// credential channel.
struct MCPEnvironmentBinding: Codable, Equatable, Hashable, Sendable {
    let variableName: String
    let credential: CredentialReference
}

struct MCPExecutionLimits: Codable, Equatable, Sendable {
    static let `default` = MCPExecutionLimits(
        startupTimeoutMilliseconds: 30_000,
        toolCallTimeoutMilliseconds: 30_000,
        maximumDiscoveredTools: 32,
        maximumOutputBytes: 1_048_576
    )

    let startupTimeoutMilliseconds: Int
    let toolCallTimeoutMilliseconds: Int
    let maximumDiscoveredTools: Int
    let maximumOutputBytes: Int
}

struct MCPReconnectConfiguration: Codable, Equatable, Sendable {
    static let `default` = MCPReconnectConfiguration(
        enabled: true,
        initialDelayMilliseconds: 500,
        maximumDelayMilliseconds: 15_000,
        maximumAttempts: 5
    )

    let enabled: Bool
    let initialDelayMilliseconds: Int
    let maximumDelayMilliseconds: Int
    let maximumAttempts: Int
}

/// A reviewed MCP definition. Arguments are a literal argv array and there is
/// deliberately no shell-command field. The working directory is project-
/// relative so it cannot silently widen the server's filesystem scope.
struct MCPServerDraft: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let displayName: String
    let transport: MCPTransport
    let serverName: String
    let executablePath: String
    let arguments: [String]
    /// Argument positions containing executable code or packages (for example
    /// the JavaScript file passed to `node`). Their bytes are fingerprinted.
    let reviewedFileArgumentIndexes: [Int]
    let projectRelativeWorkingDirectory: String?
    let environment: [MCPEnvironmentBinding]
    let allowedProviders: [MCPProviderEnablement]
    let disclosure: MCPDisclosureProfile
    let limits: MCPExecutionLimits
    let reconnect: MCPReconnectConfiguration

    init(
        id: String,
        displayName: String,
        serverName: String,
        executablePath: String,
        arguments: [String] = [],
        reviewedFileArgumentIndexes: [Int] = [],
        projectRelativeWorkingDirectory: String? = nil,
        environment: [MCPEnvironmentBinding] = [],
        allowedProviders: [MCPProviderEnablement],
        disclosure: MCPDisclosureProfile,
        limits: MCPExecutionLimits = .default,
        reconnect: MCPReconnectConfiguration = .default
    ) {
        self.id = id
        self.displayName = displayName
        transport = .stdio
        self.serverName = serverName
        self.executablePath = executablePath
        self.arguments = arguments
        self.reviewedFileArgumentIndexes = reviewedFileArgumentIndexes
        self.projectRelativeWorkingDirectory = projectRelativeWorkingDirectory
        self.environment = environment
        self.allowedProviders = allowedProviders
        self.disclosure = disclosure
        self.limits = limits
        self.reconnect = reconnect
    }
}

struct MCPExecutableFingerprint: RawRepresentable, Codable, Equatable, Hashable, Sendable {
    let rawValue: String

    init(rawValue: String) { self.rawValue = rawValue }
    init(_ rawValue: String) { self.rawValue = rawValue }
}

/// Result of resolving and hashing the exact executable that the OS would
/// launch. The optional interpreter fields bind an absolute shebang
/// interpreter as well as the script bytes.
struct MCPExecutableAudit: Codable, Equatable, Sendable {
    let declaredPath: String
    let canonicalPath: String
    let contentSHA256: String
    let byteCount: UInt64
    let ownerUID: UInt32
    let permissions: UInt16
    let interpreterCanonicalPath: String?
    let interpreterContentSHA256: String?
    let fingerprint: MCPExecutableFingerprint
}

struct MCPReviewedArgumentFileAudit: Codable, Equatable, Sendable {
    let argumentIndex: Int
    let declaredPath: String
    let canonicalPath: String
    let contentSHA256: String
    let byteCount: UInt64
    let ownerUID: UInt32
    let permissions: UInt16
}

/// Filesystem identity prevents a trust decision for one checkout from being
/// silently reused after that path is replaced with another directory.
struct MCPProjectIdentity: Codable, Equatable, Hashable, Sendable {
    let canonicalPath: String
    let ownerUID: UInt32
    let deviceID: UInt64
    let inode: UInt64
    let fingerprint: String
}

struct MCPTrustApproval: Codable, Equatable, Sendable {
    let reviewFingerprint: String
    let executableFingerprint: MCPExecutableFingerprint
    let approvedAt: Date
}

struct MCPServerTrustRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let draft: MCPServerDraft
    let project: MCPProjectIdentity
    var approval: MCPTrustApproval?
    var updatedAt: Date
}

enum MCPTrustStatus: Equatable, Sendable {
    case unreviewed
    case trusted
    case changed
}

struct MCPActivationContext: Equatable, Sendable {
    let projectRoot: URL
    let provider: ProviderID
    let providerBoundary: DataBoundary
}

/// A secret-free environment mapping for a future DSH renderer. The renderer
/// must resolve `credential` at process launch; it must never substitute the
/// value into a persisted YAML/JSON document.
struct MCPDSHEnvironmentReference: Codable, Equatable, Sendable {
    let variableName: String
    let credential: CredentialReference
}

struct MCPDSHReconnectPlan: Codable, Equatable, Sendable {
    let enabled: Bool
    let initialDelayMilliseconds: Int
    let maximumDelayMilliseconds: Int
    let maximumAttempts: Int
}

/// Fields map one-for-one to @deepseek-ai/dsh-mcp-client 0.1.1-rc.1's stdio
/// configuration, except environment values intentionally remain references.
struct MCPDSHStdioPluginPlan: Codable, Equatable, Sendable {
    static let packageName = "@deepseek-ai/dsh-mcp-client"

    let pluginID: String
    let packageName: String
    let transport: MCPTransport
    let serverName: String
    let command: String
    let arguments: [String]
    let environment: [MCPDSHEnvironmentReference]
    let workingDirectory: String
    let toolCallTimeoutMilliseconds: Int
    let failOnStartupError: Bool
    let reconnect: MCPDSHReconnectPlan
}

/// Limits which the current DSH bridge does not implement itself. An adapter
/// must enforce these before exposing the plugin to a session.
struct MCPWrapperEnforcementPlan: Codable, Equatable, Sendable {
    let startupTimeoutMilliseconds: Int
    let maximumDiscoveredTools: Int
    let maximumOutputBytes: Int
    let inheritAmbientEnvironment: Bool
}

struct MCPActivationDisclosure: Codable, Equatable, Sendable {
    let mcpServer: MCPDisclosureProfile
    let modelProvider: ProviderID
    let modelBoundary: DataBoundary

    var sendsToolMaterialOffDevice: Bool {
        mcpServer.boundary.isExternalToThisMac || modelBoundary.isExternalToThisMac
    }
}

/// Fully validated, secret-free handoff. It is data only: creating it neither
/// starts a process nor mutates DSH settings.
struct MCPActivationPlan: Codable, Equatable, Sendable {
    let serverID: String
    let reviewFingerprint: String
    let executable: MCPExecutableAudit
    let reviewedArgumentFiles: [MCPReviewedArgumentFileAudit]
    let project: MCPProjectIdentity
    let dsh: MCPDSHStdioPluginPlan
    let wrapper: MCPWrapperEnforcementPlan
    let disclosure: MCPActivationDisclosure
}
