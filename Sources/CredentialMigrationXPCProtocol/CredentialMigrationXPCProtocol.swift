import CoreFoundation
import Foundation

/// The private, app-embedded migration service has one deliberately narrow
/// capability protocol. Plaintext is never placed in arguments, environment
/// variables, paths, or NSError text: the exact source, parent directory, and
/// persistent lease cross the XPC boundary only as kernel file capabilities.
@objc public protocol LocalHarnessCredentialMigrationXPCProtocol {
    func migrate(
        source: FileHandle,
        sourceParent: FileHandle,
        lease: FileHandle,
        request: NSData,
        yamlGraph: NSData,
        withReply reply: @escaping (NSData) -> Void
    )
}

public enum CredentialMigrationXPCConstants {
    public static let serviceName = "com.angadjairath.localharness.credential-helper"
    public static let serviceBundleName = "LocalHarnessCredentialMigrationService.xpc"
    public static let leaseFileName = ".fulmar-credential-migration.lock"
    public static let acceptanceSourceName = ".fulmar-credential-xpc-acceptance"
    public static let acceptanceDirectoryPrefix = "fulmar-credential-xpc-acceptance-"
    public static let protocolVersion = 1
    public static let maximumRequestBytes = 16 * 1_024
    public static let maximumResponseBytes = 1_024
    public static let maximumGraphBytes = 8 * 1_024 * 1_024
    public static let exactYAMLModuleCount = 74
    public static let maximumSourceBytes = 4 * 1_024 * 1_024
    public static let maximumCredentialBytes = 1 * 1_024 * 1_024
    public static let maximumEntryCount = 4_096
    public static let minimumDeadlineNanoseconds: UInt64 = 50_000_000
    public static let maximumDeadlineNanoseconds: UInt64 = 3_600_000_000_000
}

public enum CredentialMigrationXPCOperation: String, Codable, Sendable {
    case migration
    case acceptance
}

public struct CredentialMigrationXPCFileIdentity: Codable, Equatable, Sendable {
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let owner: UInt32
    public let linkCount: UInt64
    public let size: Int64
    public let modifiedSeconds: Int64
    public let modifiedNanoseconds: Int64
    public let changedSeconds: Int64
    public let changedNanoseconds: Int64

    public init(
        device: UInt64,
        inode: UInt64,
        mode: UInt32,
        owner: UInt32,
        linkCount: UInt64,
        size: Int64,
        modifiedSeconds: Int64,
        modifiedNanoseconds: Int64,
        changedSeconds: Int64,
        changedNanoseconds: Int64
    ) {
        self.device = device
        self.inode = inode
        self.mode = mode
        self.owner = owner
        self.linkCount = linkCount
        self.size = size
        self.modifiedSeconds = modifiedSeconds
        self.modifiedNanoseconds = modifiedNanoseconds
        self.changedSeconds = changedSeconds
        self.changedNanoseconds = changedNanoseconds
    }
}

public struct CredentialMigrationXPCRequest: Codable, Equatable, Sendable {
    public let version: Int
    public let operation: CredentialMigrationXPCOperation
    public let acceptanceNonce: String
    public let sourceName: String
    public let source: CredentialMigrationXPCFileIdentity
    public let sourceParent: CredentialMigrationXPCFileIdentity
    public let lease: CredentialMigrationXPCFileIdentity
    public let deadlineNanoseconds: UInt64

    public init(
        version: Int = CredentialMigrationXPCConstants.protocolVersion,
        operation: CredentialMigrationXPCOperation = .migration,
        acceptanceNonce: String = "",
        sourceName: String,
        source: CredentialMigrationXPCFileIdentity,
        sourceParent: CredentialMigrationXPCFileIdentity,
        lease: CredentialMigrationXPCFileIdentity,
        deadlineNanoseconds: UInt64
    ) {
        self.version = version
        self.operation = operation
        self.acceptanceNonce = acceptanceNonce
        self.sourceName = sourceName
        self.source = source
        self.sourceParent = sourceParent
        self.lease = lease
        self.deadlineNanoseconds = deadlineNanoseconds
    }
}

public enum CredentialMigrationXPCStatus: String, Codable, Sendable {
    case success
    case busy
    case invalidRequest
    case identityMismatch
    case sourceChanged
    case invalidYAML
    case keychainFailure
    case timedOut
    case interrupted
    case recoveryRequired
    case internalFailure
}

public struct CredentialMigrationXPCResponse: Codable, Equatable, Sendable {
    public let version: Int
    public let status: CredentialMigrationXPCStatus
    public let references: Int
    public let records: Int

    public init(
        version: Int = CredentialMigrationXPCConstants.protocolVersion,
        status: CredentialMigrationXPCStatus,
        references: Int = 0,
        records: Int = 0
    ) {
        self.version = version
        self.status = status
        self.references = references
        self.records = records
    }
}

/// XPC's class whitelist is only a transport boundary. These helpers enforce
/// the exact versioned JSON object topology as well: no unknown keys, Boolean
/// integers, floating integers, duplicate-key ambiguity, alternate ordering,
/// or non-canonical whitespace is admitted before Codable sees the payload.
public enum CredentialMigrationXPCSchema {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    public static func decodeRequest(_ data: Data) -> CredentialMigrationXPCRequest? {
        guard data.count > 0,
              data.count <= CredentialMigrationXPCConstants.maximumRequestBytes,
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              exactKeys(root, [
                "acceptanceNonce", "deadlineNanoseconds", "lease", "operation", "source",
                "sourceName", "sourceParent", "version",
              ]),
              exactInteger(root["version"]),
              exactInteger(root["deadlineNanoseconds"]),
              root["operation"] is String,
              root["acceptanceNonce"] is String,
              root["sourceName"] is String,
              exactIdentity(root["source"]),
              exactIdentity(root["sourceParent"]),
              exactIdentity(root["lease"]),
              let decoded = try? JSONDecoder().decode(
                CredentialMigrationXPCRequest.self,
                from: data
              ),
              let canonical = try? encode(decoded),
              canonical == data else { return nil }
        return decoded
    }

    public static func decodeResponse(_ data: Data) -> CredentialMigrationXPCResponse? {
        guard data.count > 0,
              data.count <= CredentialMigrationXPCConstants.maximumResponseBytes,
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              exactKeys(root, ["records", "references", "status", "version"]),
              exactInteger(root["version"]),
              exactInteger(root["references"]),
              exactInteger(root["records"]),
              root["status"] is String,
              let decoded = try? JSONDecoder().decode(
                CredentialMigrationXPCResponse.self,
                from: data
              ),
              let canonical = try? encode(decoded),
              canonical == data else { return nil }
        return decoded
    }

    private static func exactIdentity(_ raw: Any?) -> Bool {
        guard let value = raw as? [String: Any],
              exactKeys(value, [
                "changedNanoseconds", "changedSeconds", "device", "inode", "linkCount",
                "mode", "modifiedNanoseconds", "modifiedSeconds", "owner", "size",
              ]) else { return false }
        return value.values.allSatisfy(exactInteger)
    }

    private static func exactKeys(_ object: [String: Any], _ keys: Set<String>) -> Bool {
        Set(object.keys) == keys
    }

    private static func exactInteger(_ raw: Any?) -> Bool {
        guard let raw else { return false }
        // CFBoolean has a distinct type ID. Floating/scientific spellings may
        // reach this point as CFNumber, but the canonical re-encode equality
        // above rejects them because the Codable fields are integer typed.
        return CFGetTypeID(raw as CFTypeRef) == CFNumberGetTypeID()
    }
}
