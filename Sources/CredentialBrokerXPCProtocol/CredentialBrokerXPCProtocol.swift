import CoreFoundation
import Foundation

@objc public protocol LocalHarnessCredentialBrokerXPCProtocol {
    func perform(
        request: NSData,
        payload: NSData,
        input: FileHandle,
        output: FileHandle,
        withReply reply: @escaping (NSData, NSData) -> Void
    )
}

public enum CredentialBrokerXPCConstants {
    public static let serviceName = "com.angadjairath.localharness.credential-broker"
    public static let serviceBundleName = "LocalHarnessCredentialBrokerService.xpc"
    public static let codeIdentifier = "com.angadjairath.localharness.credential-helper"
    public static let protocolVersion = 1
    public static let maximumRequestBytes = 8 * 1_024
    public static let maximumCredentialBytes = 1 * 1_024 * 1_024
    public static let maximumResponsePayloadBytes = 3 * 1_024 * 1_024
    public static let maximumResponseBytes = 1 * 1_024
    public static let minimumDeadlineNanoseconds: UInt64 = 50_000_000
    public static let maximumDeadlineNanoseconds: UInt64 = 35_000_000_000
}

public enum CredentialBrokerXPCOperation: String, Codable, Sendable {
    case get
    case getRecord
    case describe
    case describeRecord
    case set
    case setRecord
    case unset
    case unsetRecord
    case listRecords
    case listRecordAttention
    case modifyRecordLocked
    case backupLoadOrCreate
    case acceptance
}

public struct CredentialBrokerXPCRequest: Codable, Equatable, Sendable {
    public let version: Int
    public let operation: CredentialBrokerXPCOperation
    public let subject: String
    public let acceptanceNonce: String
    public let deadlineNanoseconds: UInt64

    public init(
        version: Int = CredentialBrokerXPCConstants.protocolVersion,
        operation: CredentialBrokerXPCOperation,
        subject: String = "",
        acceptanceNonce: String = "",
        deadlineNanoseconds: UInt64
    ) {
        self.version = version
        self.operation = operation
        self.subject = subject
        self.acceptanceNonce = acceptanceNonce
        self.deadlineNanoseconds = deadlineNanoseconds
    }
}

public enum CredentialBrokerXPCStatus: String, Codable, Sendable {
    case success
    case notFound
    case busy
    case invalidRequest
    case identityMismatch
    case authorizationRequired
    case recoveryRequired
    case unsafeState
    case persistenceFailure
    case verificationFailure
    case conflict
    case timedOut
    case interrupted
    case internalFailure
}

public struct CredentialBrokerXPCResponse: Codable, Equatable, Sendable {
    public let version: Int
    public let status: CredentialBrokerXPCStatus
    public let configured: Bool

    public init(
        version: Int = CredentialBrokerXPCConstants.protocolVersion,
        status: CredentialBrokerXPCStatus,
        configured: Bool = false
    ) {
        self.version = version
        self.status = status
        self.configured = configured
    }
}

public enum CredentialBrokerXPCSchema {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    public static func decodeRequest(_ data: Data) -> CredentialBrokerXPCRequest? {
        guard data.count > 0,
              data.count <= CredentialBrokerXPCConstants.maximumRequestBytes,
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              Set(root.keys) == [
                  "acceptanceNonce", "deadlineNanoseconds", "operation", "subject", "version",
              ],
              exactInteger(root["version"]),
              exactInteger(root["deadlineNanoseconds"]),
              root["operation"] is String,
              root["subject"] is String,
              root["acceptanceNonce"] is String,
              let decoded = try? JSONDecoder().decode(CredentialBrokerXPCRequest.self, from: data),
              let canonical = try? encode(decoded),
              canonical == data else { return nil }
        return decoded
    }

    public static func decodeResponse(_ data: Data) -> CredentialBrokerXPCResponse? {
        guard data.count > 0,
              data.count <= CredentialBrokerXPCConstants.maximumResponseBytes,
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              Set(root.keys) == ["configured", "status", "version"],
              exactInteger(root["version"]),
              CFGetTypeID(root["configured"] as CFTypeRef) == CFBooleanGetTypeID(),
              root["status"] is String,
              let decoded = try? JSONDecoder().decode(CredentialBrokerXPCResponse.self, from: data),
              let canonical = try? encode(decoded),
              canonical == data else { return nil }
        return decoded
    }

    private static func exactInteger(_ raw: Any?) -> Bool {
        guard let raw else { return false }
        return CFGetTypeID(raw as CFTypeRef) == CFNumberGetTypeID()
    }
}
