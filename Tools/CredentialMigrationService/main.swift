import Darwin
import CryptoKit
import Foundation
import JavaScriptCore
import LocalAuthentication
import LocalHarnessCredentialMigrationXPCProtocol
import LocalHarnessCredentialSecurity
import Security

private let credentialService = "app.localharness.credentials"
private let applicationBundleIdentifier = "com.angadjairath.localharness"
private let referenceExpression = try? NSRegularExpression(
    pattern: #"^[A-Za-z_][A-Za-z0-9_]*$"#
)
private let recordExpression = try? NSRegularExpression(
    pattern: #"^[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+$"#
)

private enum MigrationServiceError: Error {
    case invalidRequest
    case identityMismatch
    case sourceChanged
    case invalidYAML
    case keychainFailure
    case timedOut
    case interrupted
    case recoveryRequired

    var status: CredentialMigrationXPCStatus {
        switch self {
        case .invalidRequest: .invalidRequest
        case .identityMismatch: .identityMismatch
        case .sourceChanged: .sourceChanged
        case .invalidYAML: .invalidYAML
        case .keychainFailure: .keychainFailure
        case .timedOut: .timedOut
        case .interrupted: .interrupted
        case .recoveryRequired: .recoveryRequired
        }
    }
}

private final class MigrationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var state: CredentialMigrationXPCStatus?

    func cancel(_ reason: CredentialMigrationXPCStatus) {
        lock.lock()
        if state == nil { state = reason }
        lock.unlock()
    }

    func check() throws {
        lock.lock()
        let current = state
        lock.unlock()
        switch current {
        case .timedOut: throw MigrationServiceError.timedOut
        case .interrupted: throw MigrationServiceError.interrupted
        case .some: throw MigrationServiceError.interrupted
        case nil: return
        }
    }
}

private final class MigrationHardStopGate: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true

    func deactivate() {
        lock.lock()
        active = false
        lock.unlock()
    }

    func terminateIfActive() {
        lock.lock()
        let shouldTerminate = active
        lock.unlock()
        if shouldTerminate { _exit(124) }
    }
}

private struct MigrationCodeIdentity {
    let identifier: String
    let cdHash: Data
    let designatedRequirement: Data
    let exactRequirement: String

    static func inspect(_ url: URL, nested: Bool) throws -> MigrationCodeIdentity {
        guard url.isFileURL,
              url.path.hasPrefix("/"),
              !url.path.contains("\0"),
              url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw MigrationServiceError.identityMismatch
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else {
            throw MigrationServiceError.identityMismatch
        }
        var rawFlags = kSecCSCheckAllArchitectures | kSecCSStrictValidate
        if nested { rawFlags |= kSecCSCheckNestedCode }
        let flags = SecCSFlags(rawValue: rawFlags)
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw MigrationServiceError.identityMismatch
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation),
            &information
        ) == errSecSuccess,
              let values = information as? [String: Any],
              let identifier = values[kSecCodeInfoIdentifier as String] as? String,
              !identifier.isEmpty,
              identifier.utf8.count <= 256,
              let cdHash = values[kSecCodeInfoUnique as String] as? Data,
              !cdHash.isEmpty,
              cdHash.count <= 64,
              let rawRequirement = values[kSecCodeInfoDesignatedRequirement as String],
              CFGetTypeID(rawRequirement as CFTypeRef) == SecRequirementGetTypeID() else {
            throw MigrationServiceError.identityMismatch
        }
        let requirement = unsafeBitCast(rawRequirement as AnyObject, to: SecRequirement.self)
        var requirementData: CFData?
        var requirementString: CFString?
        guard SecRequirementCopyData(requirement, [], &requirementData) == errSecSuccess,
              let requirementData,
              (requirementData as Data).count <= 16 * 1_024,
              SecRequirementCopyString(requirement, [], &requirementString) == errSecSuccess,
              let requirementString,
              (requirementString as String).utf8.count <= 16 * 1_024,
              SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess else {
            throw MigrationServiceError.identityMismatch
        }
        let digest = cdHash.map { String(format: "%02x", $0) }.joined()
        return MigrationCodeIdentity(
            identifier: identifier,
            cdHash: cdHash,
            designatedRequirement: requirementData as Data,
            exactRequirement: "(\(requirementString as String)) and cdhash H\"\(digest)\""
        )
    }
}

private struct MigrationEntry {
    let account: String
    let value: Data
    let kind: String
}

private struct MigrationPayload {
    let entries: [MigrationEntry]
    let references: Int
    let records: Int
}

private func matches(_ value: String, _ expression: NSRegularExpression?) -> Bool {
    guard let expression else { return false }
    let range = NSRange(value.startIndex..., in: value)
    return expression.firstMatch(in: value, range: range)?.range == range
}

private func failClosedServiceStartup() -> Never {
    // Identity failures are intentionally silent and generic. A Swift fatal
    // trap would create a crash report containing bundle paths and turn an
    // expected fail-closed boundary into a noisy diagnostic artifact.
    _exit(78)
}

private func recordAccount(_ key: String) -> String {
    "record:" + Data(key.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func descriptorHasNoExtendedACL(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
        return errno == ENOENT
    }
    _ = acl_free(UnsafeMutableRawPointer(accessControlList))
    return false
}

private func identity(_ value: stat) -> CredentialMigrationXPCFileIdentity {
    CredentialMigrationXPCFileIdentity(
        device: UInt64(truncatingIfNeeded: value.st_dev),
        inode: UInt64(value.st_ino),
        mode: UInt32(value.st_mode),
        owner: UInt32(value.st_uid),
        linkCount: UInt64(value.st_nlink),
        size: Int64(value.st_size),
        modifiedSeconds: Int64(value.st_mtimespec.tv_sec),
        modifiedNanoseconds: Int64(value.st_mtimespec.tv_nsec),
        changedSeconds: Int64(value.st_ctimespec.tv_sec),
        changedNanoseconds: Int64(value.st_ctimespec.tv_nsec)
    )
}

private func validateCapabilities(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest
) throws -> stat {
    let requestMatchesOperation: Bool
    switch request.operation {
    case .migration:
        requestMatchesOperation = request.acceptanceNonce.isEmpty
            && request.sourceName == ".credentials.yaml"
    case .acceptance:
        requestMatchesOperation = validAcceptanceNonce(request.acceptanceNonce)
            && request.sourceName == CredentialMigrationXPCConstants.acceptanceSourceName
    }
    guard source >= 0, sourceParent >= 0, lease >= 0,
          request.version == CredentialMigrationXPCConstants.protocolVersion,
          requestMatchesOperation,
          request.sourceName.utf8.count <= 255,
          !request.sourceName.contains("/"),
          !request.sourceName.contains("\0"),
          request.deadlineNanoseconds >= CredentialMigrationXPCConstants.minimumDeadlineNanoseconds,
          request.deadlineNanoseconds <= CredentialMigrationXPCConstants.maximumDeadlineNanoseconds else {
        throw MigrationServiceError.invalidRequest
    }

    var sourceMetadata = stat()
    var namedSource = stat()
    var namedLease = stat()
    var parentMetadata = stat()
    var leaseMetadata = stat()
    guard fstat(source, &sourceMetadata) == 0,
          fstat(sourceParent, &parentMetadata) == 0,
          fstat(lease, &leaseMetadata) == 0,
          request.sourceName.withCString({
              fstatat(sourceParent, $0, &namedSource, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          CredentialMigrationXPCConstants.leaseFileName.withCString({
              fstatat(sourceParent, $0, &namedLease, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          identity(sourceMetadata) == request.source,
          identity(parentMetadata) == request.sourceParent,
          identity(leaseMetadata) == request.lease,
          sourceMetadata.st_dev == namedSource.st_dev,
          sourceMetadata.st_ino == namedSource.st_ino,
          sourceMetadata.st_mode & S_IFMT == S_IFREG,
          sourceMetadata.st_uid == geteuid(),
          sourceMetadata.st_nlink == 1,
          sourceMetadata.st_mode & 0o777 == 0o600,
          sourceMetadata.st_size >= 0,
          sourceMetadata.st_size <= CredentialMigrationXPCConstants.maximumSourceBytes,
          request.operation == .migration || sourceMetadata.st_size == 0,
          parentMetadata.st_mode & S_IFMT == S_IFDIR,
          parentMetadata.st_uid == geteuid(),
          parentMetadata.st_mode & 0o022 == 0,
          request.operation == .migration || parentMetadata.st_mode & 0o777 == 0o700,
          leaseMetadata.st_mode & S_IFMT == S_IFREG,
          leaseMetadata.st_uid == geteuid(),
          leaseMetadata.st_nlink == 1,
          leaseMetadata.st_mode & 0o777 == 0o600,
          leaseMetadata.st_size == 0,
          namedLease.st_dev == leaseMetadata.st_dev,
          namedLease.st_ino == leaseMetadata.st_ino,
          namedLease.st_mode & S_IFMT == S_IFREG,
          descriptorHasNoExtendedACL(source),
          descriptorHasNoExtendedACL(sourceParent),
          descriptorHasNoExtendedACL(lease) else {
        throw MigrationServiceError.identityMismatch
    }
    if request.operation == .acceptance {
        let expectedParent = "/private/tmp/"
            + CredentialMigrationXPCConstants.acceptanceDirectoryPrefix
            + request.acceptanceNonce
        var namedParent = stat()
        guard descriptorPath(sourceParent) == expectedParent,
              lstat(expectedParent, &namedParent) == 0,
              namedParent.st_dev == parentMetadata.st_dev,
              namedParent.st_ino == parentMetadata.st_ino else {
            throw MigrationServiceError.identityMismatch
        }
    }
    return sourceMetadata
}

private func validAcceptanceNonce(_ value: String) -> Bool {
    guard value.utf8.count == 36,
          let nonce = UUID(uuidString: value) else { return false }
    return nonce.uuidString.lowercased() == value
}

private func descriptorPath(_ descriptor: Int32) -> String? {
    var information = vnode_fdinfowithpath()
    let size = proc_pidfdinfo(
        getpid(),
        descriptor,
        PROC_PIDFDVNODEPATHINFO,
        &information,
        Int32(MemoryLayout<vnode_fdinfowithpath>.stride)
    )
    guard size == MemoryLayout<vnode_fdinfowithpath>.stride else { return nil }
    return withUnsafePointer(to: &information.pvip.vip_path) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
            String(cString: $0)
        }
    }
}

private func readBoundedSource(_ descriptor: Int32, expected: stat) throws -> Data {
    var result = Data()
    result.reserveCapacity(min(Int(expected.st_size), 64 * 1_024))
    var offset: Int64 = 0
    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    while result.count <= CredentialMigrationXPCConstants.maximumSourceBytes {
        let remaining = CredentialMigrationXPCConstants.maximumSourceBytes + 1 - result.count
        let requested = min(buffer.count, remaining)
        let count = buffer.withUnsafeMutableBytes { storage -> Int in
            guard let baseAddress = storage.baseAddress else { return -1 }
            return pread(descriptor, baseAddress, requested, off_t(offset))
        }
        if count > 0 {
            result.append(contentsOf: buffer.prefix(count))
            offset += Int64(count)
            continue
        }
        if count == 0 { break }
        if errno == EINTR { continue }
        throw MigrationServiceError.sourceChanged
    }
    var after = stat()
    guard result.count <= CredentialMigrationXPCConstants.maximumSourceBytes,
          result.count == Int(expected.st_size),
          fstat(descriptor, &after) == 0,
          identity(after) == identity(expected) else {
        throw MigrationServiceError.sourceChanged
    }
    return result
}

private let yamlLoader = #"""
"use strict";
globalThis.console = Object.freeze({ log() {}, warn() {}, error() {} });
globalThis.__fulmarParse = function(graphJSON, source) {
  const graph = JSON.parse(graphJSON);
  const names = Object.keys(graph);
  if (names.length !== 74 || !Object.prototype.hasOwnProperty.call(graph, "index.js")) {
    throw new Error("invalid graph");
  }
  const cache = Object.create(null);
  const resolve = (parent, request) => {
    if (typeof request !== "string" || request.length === 0 || request[0] !== ".") {
      throw new Error("external module");
    }
    const base = parent.includes("/") ? parent.slice(0, parent.lastIndexOf("/")) : "";
    const parts = (base + "/" + request).split("/");
    const normalized = [];
    for (const part of parts) {
      if (part === "" || part === ".") continue;
      if (part === "..") {
        if (normalized.length === 0) throw new Error("module escape");
        normalized.pop();
      } else {
        if (!/^[A-Za-z0-9._-]+$/.test(part)) throw new Error("module name");
        normalized.push(part);
      }
    }
    let name = normalized.join("/");
    if (!name.endsWith(".js")) name += ".js";
    return name;
  };
  const load = (name) => {
    if (!Object.prototype.hasOwnProperty.call(graph, name) || typeof graph[name] !== "string") {
      throw new Error("missing module");
    }
    if (cache[name]) return cache[name].exports;
    const module = { exports: {} };
    cache[name] = module;
    const localRequire = (request) => {
      if (request === "process") return Object.freeze({ env: Object.freeze({}), emitWarning() {} });
      if (request === "buffer") return Object.freeze({ Buffer: undefined });
      return load(resolve(name, request));
    };
    const evaluate = new Function(
      "require", "module", "exports", "__filename", "__dirname",
      "\"use strict\";\n" + graph[name] + "\n//# sourceURL=fulmar-yaml-graph/" + name
    );
    evaluate(localRequire, module, module.exports, name,
      name.includes("/") ? name.slice(0, name.lastIndexOf("/")) : "");
    return module.exports;
  };
  const yaml = load("index.js");
  if (!yaml || typeof yaml.parseDocument !== "function") throw new Error("missing parser");
  const document = yaml.parseDocument(source, { prettyErrors: false, uniqueKeys: true });
  if (!document || !Array.isArray(document.errors) || document.errors.length !== 0) {
    throw new Error("invalid yaml");
  }
  const root = document.toJS() ?? {};
  if (root && typeof root === "object" && !Array.isArray(root)
      && Object.prototype.hasOwnProperty.call(root, "version")) {
    const versionNode = document.get("version", true);
    if (!versionNode || versionNode.value !== 1
        || versionNode.source !== "1" || versionNode.type !== "PLAIN") {
      throw new Error("invalid version scalar");
    }
  }
  return JSON.stringify(root);
};
"""#

private func parseYAML(source: Data, graphData: Data) throws -> MigrationPayload {
    guard graphData.count > 0,
          graphData.count <= CredentialMigrationXPCConstants.maximumGraphBytes,
          let graph = try? JSONDecoder().decode([String: String].self, from: graphData),
          let canonicalGraph = try? CredentialMigrationXPCSchema.encode(graph),
          canonicalGraph == graphData,
          graph.count == CredentialMigrationXPCConstants.exactYAMLModuleCount,
          graph["index.js"] != nil else {
        throw MigrationServiceError.invalidRequest
    }
    var totalBytes = 0
    for (name, value) in graph {
        guard name.range(
            of: #"^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.js$"#,
            options: .regularExpression
        ) != nil,
              !name.hasPrefix("."),
              !value.isEmpty else {
            throw MigrationServiceError.invalidRequest
        }
        totalBytes += value.utf8.count
        guard totalBytes <= CredentialMigrationXPCConstants.maximumGraphBytes else {
            throw MigrationServiceError.invalidRequest
        }
    }
    guard let graphJSON = String(data: graphData, encoding: .utf8),
          let sourceText = String(data: source, encoding: .utf8),
          let context = JSContext() else {
        throw MigrationServiceError.invalidYAML
    }
    context.exceptionHandler = { _, _ in }
    context.evaluateScript(yamlLoader)
    guard context.exception == nil,
          let parser = context.objectForKeyedSubscript("__fulmarParse"),
          !parser.isUndefined,
          let result = parser.call(withArguments: [graphJSON, sourceText]),
          context.exception == nil,
          !result.isUndefined,
          !result.isNull,
          let json = result.toString(),
          json.utf8.count <= CredentialMigrationXPCConstants.maximumSourceBytes,
          let rootData = json.data(using: .utf8),
          let rootObject = try? JSONSerialization.jsonObject(with: rootData),
          let root = rootObject as? [String: Any] else {
        throw MigrationServiceError.invalidYAML
    }
    return try validateRoot(root)
}

private func validateRoot(_ root: [String: Any]) throws -> MigrationPayload {
    let refs: [String: Any]
    let records: [String: Any]
    if root.isEmpty {
        refs = [:]
        records = [:]
    } else if let rawVersion = root["version"] {
        guard Set(root.keys).isSubset(of: ["version", "refs", "records"]),
              CFGetTypeID(rawVersion as CFTypeRef) == CFNumberGetTypeID(),
              let version = rawVersion as? NSNumber,
              !CFNumberIsFloatType(version),
              version.int64Value == 1,
              (root["refs"] ?? [:]) is [String: Any],
              (root["records"] ?? [:]) is [String: Any] else {
            throw MigrationServiceError.invalidYAML
        }
        refs = (root["refs"] as? [String: Any]) ?? [:]
        records = (root["records"] as? [String: Any]) ?? [:]
    } else {
        refs = root
        records = [:]
    }
    guard refs.count <= CredentialMigrationXPCConstants.maximumEntryCount,
          records.count <= CredentialMigrationXPCConstants.maximumEntryCount - refs.count else {
        throw MigrationServiceError.invalidYAML
    }

    var entries: [MigrationEntry] = []
    entries.reserveCapacity(refs.count + records.count)
    for key in refs.keys.sorted() {
        guard matches(key, referenceExpression),
              let text = refs[key] as? String,
              !text.isEmpty,
              let value = text.data(using: .utf8),
              value.count <= CredentialMigrationXPCConstants.maximumCredentialBytes else {
            throw MigrationServiceError.invalidYAML
        }
        entries.append(MigrationEntry(account: "ref:" + key, value: value, kind: "reference"))
    }
    for key in records.keys.sorted() {
        guard matches(key, recordExpression),
              let record = records[key] as? [String: Any],
              let kind = validateRecord(record),
              JSONSerialization.isValidJSONObject(record),
              let value = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
              !value.isEmpty,
              value.count <= CredentialMigrationXPCConstants.maximumCredentialBytes else {
            throw MigrationServiceError.invalidYAML
        }
        entries.append(MigrationEntry(account: recordAccount(key), value: value, kind: kind))
    }
    return MigrationPayload(entries: entries, references: refs.count, records: records.count)
}

private func validateRecord(_ record: [String: Any]) -> String? {
    guard let kind = record["kind"] as? String else { return nil }
    switch kind {
    case "api-key":
        guard Set(record.keys).isSubset(of: ["kind", "key", "env"]) else { return nil }
        if let rawKey = record["key"] {
            guard let key = rawKey as? String, !key.isEmpty else { return nil }
        }
        if let rawEnvironment = record["env"] {
            guard let environment = rawEnvironment as? [String: Any] else { return nil }
            for (name, rawValue) in environment {
                guard matches(name, referenceExpression),
                      let value = rawValue as? String,
                      !value.isEmpty else { return nil }
            }
        }
        return kind
    case "grant":
        guard Set(record.keys) == ["kind", "payload"],
              let payload = record["payload"],
              validCanonicalJSON(payload, depth: 0) else { return nil }
        return kind
    default:
        return nil
    }
}

private func validCanonicalJSON(_ value: Any, depth: Int) -> Bool {
    guard depth <= 64 else { return false }
    if value is NSNull || value is String || value is Bool { return true }
    if let number = value as? NSNumber { return number.doubleValue.isFinite }
    if let array = value as? [Any] {
        return array.count <= CredentialMigrationXPCConstants.maximumEntryCount
            && array.allSatisfy { validCanonicalJSON($0, depth: depth + 1) }
    }
    if let object = value as? [String: Any] {
        return object.count <= CredentialMigrationXPCConstants.maximumEntryCount
            && object.allSatisfy {
                $0.key.utf8.count <= 1_024 && validCanonicalJSON($0.value, depth: depth + 1)
            }
    }
    return false
}

private func disableKeychainInteraction() throws {
    guard let securityHandle = dlopen(
        "/System/Library/Frameworks/Security.framework/Security",
        RTLD_LAZY | RTLD_LOCAL
    ), let symbol = dlsym(securityHandle, "SecKeychainSetUserInteractionAllowed") else {
        throw MigrationServiceError.keychainFailure
    }
    typealias Setter = @convention(c) (UInt8) -> OSStatus
    let setter = unsafeBitCast(symbol, to: Setter.self)
    guard setter(0) == errSecSuccess else { throw MigrationServiceError.keychainFailure }
}

private func baseQuery(_ account: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: credentialService,
        kSecAttrAccount as String: account,
    ]
}

private func nonInteractiveQuery(_ account: String) -> [String: Any] {
    var query = baseQuery(account)
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    return query
}

private struct MigrationKeychainValueStore: CredentialValueStore {
    func read(account: String) throws -> Data? {
        var query = nonInteractiveQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecParam {
            query = baseQuery(account)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            result = nil
            status = SecItemCopyMatching(query as CFDictionary, &result)
        }
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let value = result as? Data else {
            throw keychainError(status)
        }
        return value
    }

    func add(account: String, value: Data) throws {
        var query = baseQuery(account)
        query[kSecValueData as String] = value
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem { throw CredentialValueStoreError.duplicate }
        guard status == errSecSuccess else { throw keychainError(status) }
    }

    func replace(account: String, value: Data) throws {
        let replacement: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(
            nonInteractiveQuery(account) as CFDictionary,
            replacement as CFDictionary
        )
        if status == errSecParam {
            status = SecItemUpdate(baseQuery(account) as CFDictionary, replacement as CFDictionary)
        }
        guard status == errSecSuccess else { throw keychainError(status) }
    }

    func delete(account: String) throws {
        var status = SecItemDelete(nonInteractiveQuery(account) as CFDictionary)
        if status == errSecParam { status = SecItemDelete(baseQuery(account) as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError(status)
        }
    }

    private func keychainError(_ status: OSStatus) -> CredentialValueStoreError {
        if status == errSecInteractionNotAllowed || status == errSecAuthFailed {
            return .authorizationRequired
        }
        return .status(status)
    }
}

private let receiptAuthenticationService =
    "com.angadjairath.localharness.credential-migration-receipt"
private let receiptAuthenticationAccount = "receipt-authentication-v1"

private struct MigrationCredentialContext {
    let coordinator: CredentialTransactionCoordinator
    let receiptStore: CredentialMigrationReceiptStore
}

private func credentialMetadataCapability() throws -> CredentialPrivateDirectoryCapability {
    guard let home = loginHomeDirectory() else {
        throw MigrationServiceError.keychainFailure
    }
    do {
        return try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(home: home)
    } catch {
        throw MigrationServiceError.keychainFailure
    }
}

private func receiptAuthenticationQuery(nonInteractive: Bool) -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: receiptAuthenticationService,
        kSecAttrAccount as String: receiptAuthenticationAccount,
    ]
    if nonInteractive {
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
    }
    return query
}

private func readReceiptAuthenticationKey() throws -> Data? {
    var query = receiptAuthenticationQuery(nonInteractive: true)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    var status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecParam {
        query = receiptAuthenticationQuery(nonInteractive: false)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        result = nil
        status = SecItemCopyMatching(query as CFDictionary, &result)
    }
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let key = result as? Data, key.count == 32 else {
        throw MigrationServiceError.keychainFailure
    }
    return key
}

private func receiptAuthenticationKey() throws -> Data {
    if let existing = try readReceiptAuthenticationKey() { return existing }
    var bytes = Data(count: 32)
    let generated: OSStatus = bytes.withUnsafeMutableBytes { storage in
        guard storage.count == 32, let baseAddress = storage.baseAddress else {
            return errSecParam
        }
        return SecRandomCopyBytes(kSecRandomDefault, storage.count, baseAddress)
    }
    guard generated == errSecSuccess else { throw MigrationServiceError.keychainFailure }
    var addition = receiptAuthenticationQuery(nonInteractive: false)
    addition[kSecValueData as String] = bytes
    addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(addition as CFDictionary, nil)
    if status == errSecDuplicateItem, let raced = try readReceiptAuthenticationKey() {
        return raced
    }
    guard status == errSecSuccess else { throw MigrationServiceError.keychainFailure }
    return bytes
}

private func credentialContext() throws -> MigrationCredentialContext {
    do {
        let metadata = try credentialMetadataCapability()
        return MigrationCredentialContext(
            coordinator: CredentialTransactionCoordinator(
                stateStore: try CredentialFileStateStore(directoryCapability: metadata),
                valueStore: MigrationKeychainValueStore()
            ),
            receiptStore: try CredentialMigrationReceiptStore(
                directoryCapability: metadata,
                authenticationKey: receiptAuthenticationKey()
            )
        )
    } catch {
        throw MigrationServiceError.keychainFailure
    }
}

private func runAcceptanceMetadataCanary(nonce: String) throws {
    let capability = try credentialMetadataCapability()
    let directory = try capability.duplicateDescriptor()
    defer { _ = close(directory) }
    let name = ".credential-xpc-acceptance-" + nonce
    guard name.utf8.count <= Int(MAXNAMLEN),
          !name.contains("/"),
          !name.contains("\0") else {
        throw MigrationServiceError.identityMismatch
    }
    let descriptor = name.withCString {
        openat(
            directory,
            $0,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
    }
    guard descriptor >= 0 else { throw MigrationServiceError.identityMismatch }
    var closed = false
    defer {
        if !closed { _ = close(descriptor) }
        _ = name.withCString { unlinkat(directory, $0, 0) }
        _ = fsync(directory)
    }
    var metadata = stat()
    var named = stat()
    guard fstat(descriptor, &metadata) == 0,
          name.withCString({
              fstatat(directory, $0, &named, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          metadata.st_dev == named.st_dev,
          metadata.st_ino == named.st_ino,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == geteuid(),
          metadata.st_nlink == 1,
          metadata.st_mode & 0o777 == 0o600,
          metadata.st_size == 0,
          descriptorHasNoExtendedACL(descriptor),
          fsync(descriptor) == 0,
          close(descriptor) == 0 else {
        throw MigrationServiceError.identityMismatch
    }
    closed = true
    guard name.withCString({ unlinkat(directory, $0, 0) }) == 0,
          fsync(directory) == 0 else {
        throw MigrationServiceError.identityMismatch
    }
}

private func loginHomeDirectory() -> URL? {
    guard getuid() == geteuid(), geteuid() != 0 else { return nil }
    let requested = sysconf(_SC_GETPW_R_SIZE_MAX)
    let capacity = requested > 0
        ? min(max(Int(requested), 16 * 1_024), 1 * 1_024 * 1_024)
        : 16 * 1_024
    var record = passwd()
    var result: UnsafeMutablePointer<passwd>?
    var buffer = [CChar](repeating: 0, count: capacity)
    let status = buffer.withUnsafeMutableBufferPointer { storage -> Int32 in
        guard let baseAddress = storage.baseAddress else { return EINVAL }
        return getpwuid_r(geteuid(), &record, baseAddress, storage.count, &result)
    }
    guard status == 0,
          result != nil,
          record.pw_uid == geteuid(),
          let directory = record.pw_dir,
          directory.pointee != 0 else { return nil }
    let rawPath = String(cString: directory)
    guard rawPath.hasPrefix("/"), rawPath.utf8.count <= Int(PATH_MAX) else { return nil }
    let home = URL(fileURLWithPath: rawPath, isDirectory: true).standardizedFileURL
    var metadata = stat()
    var canonical = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard lstat(home.path, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o022 == 0,
          realpath(home.path, &canonical) != nil,
          String(cString: canonical) == home.path else { return nil }
    return home
}

private func assertSourceUnchanged(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest,
    expected: stat,
    expectedBytes: Data
) throws {
    var descriptorMetadata = stat()
    var pathMetadata = stat()
    var leaseMetadata = stat()
    var namedLease = stat()
    guard fstat(source, &descriptorMetadata) == 0,
          request.sourceName.withCString({
              fstatat(sourceParent, $0, &pathMetadata, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          fstat(lease, &leaseMetadata) == 0,
          CredentialMigrationXPCConstants.leaseFileName.withCString({
              fstatat(sourceParent, $0, &namedLease, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          identity(descriptorMetadata) == identity(expected),
          identity(pathMetadata) == identity(expected),
          identity(leaseMetadata) == request.lease,
          identity(namedLease) == request.lease,
          descriptorHasNoExtendedACL(source),
          descriptorHasNoExtendedACL(lease),
          try readBoundedSource(source, expected: expected) == expectedBytes else {
        throw MigrationServiceError.sourceChanged
    }
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func receiptEvidence(
    _ receipt: CredentialMigrationReceipt
) -> CredentialMigrationBatchEvidence {
    CredentialMigrationBatchEvidence(entries: receipt.entries.map {
        CredentialMigrationBatchEvidence.Entry(
            account: $0.account,
            kind: $0.kind,
            valueSHA256: $0.valueSHA256
        )
    })
}

private func scrubbedSourceIsBound(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest,
    original: stat
) -> Bool {
    var scrubbed = stat()
    var namedSource = stat()
    var leaseMetadata = stat()
    var namedLease = stat()
    return fstat(source, &scrubbed) == 0
        && request.sourceName.withCString({
            fstatat(sourceParent, $0, &namedSource, AT_SYMLINK_NOFOLLOW)
        }) == 0
        && fstat(lease, &leaseMetadata) == 0
        && CredentialMigrationXPCConstants.leaseFileName.withCString({
            fstatat(sourceParent, $0, &namedLease, AT_SYMLINK_NOFOLLOW)
        }) == 0
        && scrubbed.st_dev == original.st_dev
        && scrubbed.st_ino == original.st_ino
        && scrubbed.st_mode & S_IFMT == S_IFREG
        && scrubbed.st_uid == geteuid()
        && scrubbed.st_nlink == 1
        && scrubbed.st_mode & 0o777 == 0o600
        && scrubbed.st_size == 0
        && namedSource.st_dev == scrubbed.st_dev
        && namedSource.st_ino == scrubbed.st_ino
        && namedSource.st_size == 0
        && identity(leaseMetadata) == request.lease
        && identity(namedLease) == request.lease
        && descriptorHasNoExtendedACL(source)
        && descriptorHasNoExtendedACL(lease)
}

private func verifyScrubbedMigration(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest,
    sourceIdentity: stat,
    context: MigrationCredentialContext,
    cancellation: MigrationCancellation
) throws -> CredentialMigrationXPCResponse {
    try cancellation.check()
    guard let receipt = try? context.receiptStore.read(),
          receipt.sourceDevice == UInt64(truncatingIfNeeded: sourceIdentity.st_dev),
          receipt.sourceInode == UInt64(sourceIdentity.st_ino),
          scrubbedSourceIsBound(
            source: source,
            sourceParent: sourceParent,
            lease: lease,
            request: request,
            original: sourceIdentity
          ),
          (try? context.coordinator.verifyMigrationEvidence(receiptEvidence(receipt))) == true else {
        throw MigrationServiceError.recoveryRequired
    }
    try cancellation.check()
    if receipt.phase == .prepared {
        do {
            _ = try CredentialMigrationCommitBoundary.finalizePreparedReceipt(
                receipt,
                receiptStore: context.receiptStore
            ) {
                guard fsync(source) == 0,
                      scrubbedSourceIsBound(
                        source: source,
                        sourceParent: sourceParent,
                        lease: lease,
                        request: request,
                        original: sourceIdentity
                      ) else {
                    throw MigrationServiceError.recoveryRequired
                }
            }
        } catch {
            throw MigrationServiceError.recoveryRequired
        }
    }
    return CredentialMigrationXPCResponse(
        status: .success,
        references: receipt.references,
        records: receipt.records
    )
}

private func performMigration(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest,
    graphData: Data,
    cancellation: MigrationCancellation
) throws -> CredentialMigrationXPCResponse {
    try cancellation.check()
    guard request.operation == .migration else {
        throw MigrationServiceError.invalidRequest
    }
    let sourceIdentity = try validateCapabilities(
        source: source,
        sourceParent: sourceParent,
        lease: lease,
        request: request
    )
    let sourceBytes = try readBoundedSource(source, expected: sourceIdentity)
    try cancellation.check()
    // Rebind both exact sibling names immediately before the first Keychain
    // operation. Parsing and later commit repeat the same proof, so a renamed
    // source or lease can never authorize a different inode.
    try assertSourceUnchanged(
        source: source,
        sourceParent: sourceParent,
        lease: lease,
        request: request,
        expected: sourceIdentity,
        expectedBytes: sourceBytes
    )
    try disableKeychainInteraction()
    let context = try credentialContext()
    if sourceIdentity.st_size == 0 {
        return try verifyScrubbedMigration(
            source: source,
            sourceParent: sourceParent,
            lease: lease,
            request: request,
            sourceIdentity: sourceIdentity,
            context: context,
            cancellation: cancellation
        )
    }

    let payload = try parseYAML(source: sourceBytes, graphData: graphData)
    try cancellation.check()
    let entries = payload.entries.map {
        CredentialMigrationBatchEntry(account: $0.account, value: $0.value, kind: $0.kind)
    }
    let outcome: CredentialMigrationCommitOutcome
    do {
        outcome = try context.coordinator.withAtomicMigrationBatch(entries: entries) { evidence in
            let prepared = CredentialMigrationReceipt(
                phase: .prepared,
                sourceDevice: UInt64(truncatingIfNeeded: sourceIdentity.st_dev),
                sourceInode: UInt64(sourceIdentity.st_ino),
                sourceSize: Int64(sourceIdentity.st_size),
                sourceSHA256: sha256(sourceBytes),
                references: payload.references,
                records: payload.records,
                entries: evidence.entries.map {
                    CredentialMigrationReceiptEntry(
                        account: $0.account,
                        kind: $0.kind,
                        valueSHA256: $0.valueSHA256
                    )
                }
            )
            return try CredentialMigrationCommitBoundary.commit(
                receiptStore: context.receiptStore,
                preparedReceipt: prepared,
                validateBeforeScrub: {
                    try cancellation.check()
                    try assertSourceUnchanged(
                        source: source,
                        sourceParent: sourceParent,
                        lease: lease,
                        request: request,
                        expected: sourceIdentity,
                        expectedBytes: sourceBytes
                    )
                },
                truncate: {
                    guard ftruncate(source, 0) == 0 else {
                        try assertSourceUnchanged(
                            source: source,
                            sourceParent: sourceParent,
                            lease: lease,
                            request: request,
                            expected: sourceIdentity,
                            expectedBytes: sourceBytes
                        )
                        throw MigrationServiceError.sourceChanged
                    }
                },
                synchronizeAndValidateScrubbedSource: {
                    guard fsync(source) == 0,
                          scrubbedSourceIsBound(
                            source: source,
                            sourceParent: sourceParent,
                            lease: lease,
                            request: request,
                            original: sourceIdentity
                          ) else {
                        throw MigrationServiceError.recoveryRequired
                    }
                }
            )
        }
    } catch let error as MigrationServiceError {
        throw error
    } catch {
        throw MigrationServiceError.keychainFailure
    }
    guard outcome == .success else { throw MigrationServiceError.recoveryRequired }
    return CredentialMigrationXPCResponse(
        status: .success,
        references: payload.references,
        records: payload.records
    )
}

private func performAcceptance(
    source: Int32,
    sourceParent: Int32,
    lease: Int32,
    request: CredentialMigrationXPCRequest,
    cancellation: MigrationCancellation
) throws -> CredentialMigrationXPCResponse {
    try cancellation.check()
    guard request.operation == .acceptance else {
        throw MigrationServiceError.invalidRequest
    }
    let sourceIdentity = try validateCapabilities(
        source: source,
        sourceParent: sourceParent,
        lease: lease,
        request: request
    )
    guard sourceIdentity.st_size == 0 else {
        throw MigrationServiceError.identityMismatch
    }
    try assertSourceUnchanged(
        source: source,
        sourceParent: sourceParent,
        lease: lease,
        request: request,
        expected: sourceIdentity,
        expectedBytes: Data()
    )
    try runAcceptanceMetadataCanary(nonce: request.acceptanceNonce)
    try cancellation.check()
    return CredentialMigrationXPCResponse(status: .success)
}

private final class CredentialMigrationService: NSObject, LocalHarnessCredentialMigrationXPCProtocol {
    private let cancellation = MigrationCancellation()
    private let admission: CredentialMigrationServiceAdmission

    init(admission: CredentialMigrationServiceAdmission) {
        self.admission = admission
    }

    func invalidate() {
        cancellation.cancel(.interrupted)
    }

    func migrate(
        source: FileHandle,
        sourceParent: FileHandle,
        lease: FileHandle,
        request: NSData,
        yamlGraph: NSData,
        withReply reply: @escaping (NSData) -> Void
    ) {
        guard admission.begin() else {
            reply(encode(CredentialMigrationXPCResponse(status: .busy)))
            return
        }
        defer { admission.finish() }
        let response: CredentialMigrationXPCResponse
        do {
            guard request.length > 0,
                  request.length <= CredentialMigrationXPCConstants.maximumRequestBytes,
                  let decoded = CredentialMigrationXPCSchema.decodeRequest(request as Data),
                  decoded.version == CredentialMigrationXPCConstants.protocolVersion,
                  (decoded.operation == .migration
                    ? yamlGraph.length > 0
                        && yamlGraph.length <= CredentialMigrationXPCConstants.maximumGraphBytes
                    : yamlGraph.length == 0) else {
                throw MigrationServiceError.invalidRequest
            }
            let timeout = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
            let hardStop = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
            let (deadlineNanoseconds, deadlineOverflow) = DispatchTime.now().uptimeNanoseconds
                .addingReportingOverflow(decoded.deadlineNanoseconds)
            let (hardStopNanoseconds, hardStopOverflow) = deadlineNanoseconds
                .addingReportingOverflow(250_000_000)
            guard !deadlineOverflow, !hardStopOverflow else {
                throw MigrationServiceError.invalidRequest
            }
            let deadline = DispatchTime(uptimeNanoseconds: deadlineNanoseconds)
            let hardStopDeadline = DispatchTime(uptimeNanoseconds: hardStopNanoseconds)
            let hardStopGate = MigrationHardStopGate()
            timeout.schedule(deadline: deadline)
            timeout.setEventHandler {
                self.cancellation.cancel(.timedOut)
            }
            hardStop.schedule(deadline: hardStopDeadline)
            hardStop.setEventHandler {
                hardStopGate.terminateIfActive()
            }
            timeout.resume()
            hardStop.resume()
            defer {
                hardStopGate.deactivate()
                timeout.cancel()
                hardStop.cancel()
            }
            switch decoded.operation {
            case .migration:
                response = try performMigration(
                    source: source.fileDescriptor,
                    sourceParent: sourceParent.fileDescriptor,
                    lease: lease.fileDescriptor,
                    request: decoded,
                    graphData: yamlGraph as Data,
                    cancellation: cancellation
                )
            case .acceptance:
                response = try performAcceptance(
                    source: source.fileDescriptor,
                    sourceParent: sourceParent.fileDescriptor,
                    lease: lease.fileDescriptor,
                    request: decoded,
                    cancellation: cancellation
                )
            }
        } catch let error as MigrationServiceError {
            response = CredentialMigrationXPCResponse(status: error.status)
        } catch {
            response = CredentialMigrationXPCResponse(status: .internalFailure)
        }
        reply(encode(response))
    }

    private func encode(_ response: CredentialMigrationXPCResponse) -> NSData {
        let encoded = (try? CredentialMigrationXPCSchema.encode(response))
            ?? Data(#"{"records":0,"references":0,"status":"internalFailure","version":1}"#.utf8)
        return encoded as NSData
    }
}

private final class CredentialMigrationServiceAdmission: @unchecked Sendable {
    private let lock = NSLock()
    private var active = false

    func begin() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !active else { return false }
        active = true
        return true
    }

    func finish() {
        lock.lock()
        active = false
        lock.unlock()
    }
}

private final class CredentialMigrationListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let exactApplicationRequirement: String
    private let admission = CredentialMigrationServiceAdmission()

    override init() {
        do {
            let serviceBundle = Bundle.main.bundleURL.standardizedFileURL
            let xpcDirectory = serviceBundle.deletingLastPathComponent()
            let contents = xpcDirectory.deletingLastPathComponent()
            let application = contents.deletingLastPathComponent()
            let helper = contents
                .appendingPathComponent("MacOS", isDirectory: true)
                .appendingPathComponent("LocalHarnessCredentialHelper", isDirectory: false)
            guard Bundle.main.bundleIdentifier == CredentialMigrationXPCConstants.serviceName,
                  serviceBundle.lastPathComponent == CredentialMigrationXPCConstants.serviceBundleName,
                  xpcDirectory.lastPathComponent == "XPCServices",
                  contents.lastPathComponent == "Contents",
                  application.pathExtension == "app",
                  Bundle(url: application)?.bundleIdentifier == applicationBundleIdentifier else {
                failClosedServiceStartup()
            }
            let serviceIdentity = try MigrationCodeIdentity.inspect(serviceBundle, nested: false)
            let helperIdentity = try MigrationCodeIdentity.inspect(helper, nested: false)
            let appIdentity = try MigrationCodeIdentity.inspect(application, nested: true)
            guard serviceIdentity.identifier == CredentialMigrationXPCConstants.serviceName,
                  helperIdentity.identifier == CredentialMigrationXPCConstants.serviceName,
                  serviceIdentity.designatedRequirement == helperIdentity.designatedRequirement,
                  appIdentity.identifier == applicationBundleIdentifier else {
                failClosedServiceStartup()
            }
            exactApplicationRequirement = appIdentity.exactRequirement
        } catch {
            failClosedServiceStartup()
        }
        super.init()
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.setCodeSigningRequirement(exactApplicationRequirement)
        let service = CredentialMigrationService(admission: admission)
        connection.exportedInterface = NSXPCInterface(
            with: LocalHarnessCredentialMigrationXPCProtocol.self
        )
        connection.exportedObject = service
        connection.interruptionHandler = { [weak service] in service?.invalidate() }
        connection.invalidationHandler = { [weak service] in service?.invalidate() }
        connection.resume()
        return true
    }
}

private let listenerDelegate = CredentialMigrationListenerDelegate()
private let listener = NSXPCListener.service()
listener.delegate = listenerDelegate
listener.resume()
