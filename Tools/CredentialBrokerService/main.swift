import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import LocalHarnessCredentialBrokerXPCProtocol
import LocalHarnessCredentialSecurity
import Security

private let credentialService = "app.localharness.credentials"
private let backupAuthenticationService = "com.angadjairath.localharness.backup-authentication"
private let backupAuthenticationAccount = "state-backup-manifest-v2"
private let acceptanceService = "com.angadjairath.localharness.credential-broker-acceptance"
private let applicationBundleIdentifier = "com.angadjairath.localharness"
private let referencePattern = try? NSRegularExpression(pattern: #"^[A-Za-z_][A-Za-z0-9_]*$"#)
private let recordPattern = try? NSRegularExpression(pattern: #"^[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+$"#)

private enum BrokerError: Error {
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

    var status: CredentialBrokerXPCStatus {
        switch self {
        case .invalidRequest: .invalidRequest
        case .identityMismatch: .identityMismatch
        case .authorizationRequired: .authorizationRequired
        case .recoveryRequired: .recoveryRequired
        case .unsafeState: .unsafeState
        case .persistenceFailure: .persistenceFailure
        case .verificationFailure: .verificationFailure
        case .conflict: .conflict
        case .timedOut: .timedOut
        case .interrupted: .interrupted
        case .internalFailure: .internalFailure
        }
    }
}

private func failClosedStartup() -> Never { _exit(78) }

private struct CodeIdentity {
    let identifier: String
    let designatedRequirement: Data
    let exactRequirement: String

    static func inspect(_ url: URL, nested: Bool) throws -> CodeIdentity {
        guard url.isFileURL,
              url.path.hasPrefix("/"),
              !url.path.contains("\0"),
              url.path == url.standardizedFileURL.path,
              url.path == url.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw BrokerError.identityMismatch
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else { throw BrokerError.identityMismatch }
        var rawFlags = kSecCSCheckAllArchitectures | kSecCSStrictValidate
        if nested { rawFlags |= kSecCSCheckNestedCode }
        let flags = SecCSFlags(rawValue: rawFlags)
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw BrokerError.identityMismatch
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
            throw BrokerError.identityMismatch
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
            throw BrokerError.identityMismatch
        }
        let digest = cdHash.map { String(format: "%02x", $0) }.joined()
        return CodeIdentity(
            identifier: identifier,
            designatedRequirement: requirementData as Data,
            exactRequirement: "(\(requirementString as String)) and cdhash H\"\(digest)\""
        )
    }
}

private final class Cancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var status: CredentialBrokerXPCStatus?

    func cancel(_ value: CredentialBrokerXPCStatus) {
        lock.lock()
        if status == nil { status = value }
        lock.unlock()
    }

    func check() throws {
        lock.lock()
        let value = status
        lock.unlock()
        switch value {
        case .timedOut: throw BrokerError.timedOut
        case .some: throw BrokerError.interrupted
        case nil: return
        }
    }
}

private final class HardStopGate: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true

    func deactivate() { lock.withLock { active = false } }
    func terminateIfActive() {
        let terminate = lock.withLock { active }
        if terminate { _exit(124) }
    }
}

private func matches(_ value: String, _ expression: NSRegularExpression?) -> Bool {
    guard let expression else { return false }
    let range = NSRange(value.startIndex..., in: value)
    return expression.firstMatch(in: value, range: range)?.range == range
}

private func recordAccount(_ subject: String) -> String {
    "record:" + Data(subject.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func decodeRecordAccount(_ account: String) -> String? {
    guard account.hasPrefix("record:") else { return nil }
    var encoded = String(account.dropFirst("record:".count))
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while !encoded.count.isMultiple(of: 4) { encoded.append("=") }
    guard let data = Data(base64Encoded: encoded),
          let key = String(data: data, encoding: .utf8),
          matches(key, recordPattern) else { return nil }
    return key
}

private func validCanonicalJSON(_ value: Any, depth: Int) -> Bool {
    guard depth <= 64 else { return false }
    if value is NSNull || value is String || value is Bool { return true }
    if let number = value as? NSNumber { return number.doubleValue.isFinite }
    if let array = value as? [Any] {
        return array.count <= 4_096
            && array.allSatisfy { validCanonicalJSON($0, depth: depth + 1) }
    }
    if let object = value as? [String: Any] {
        return object.count <= 4_096
            && object.allSatisfy {
                $0.key.utf8.count <= 1_024 && validCanonicalJSON($0.value, depth: depth + 1)
            }
    }
    return false
}

private func validatedRecord(_ data: Data) -> (data: Data, kind: String)? {
    guard !data.isEmpty,
          data.count <= CredentialBrokerXPCConstants.maximumCredentialBytes,
          let object = try? JSONSerialization.jsonObject(with: data),
          let record = object as? [String: Any],
          let kind = record["kind"] as? String else { return nil }
    switch kind {
    case "api-key":
        guard Set(record.keys).isSubset(of: ["kind", "key", "env"]) else { return nil }
        if let raw = record["key"], !(raw is String) { return nil }
        if let key = record["key"] as? String, key.isEmpty { return nil }
        if let rawEnvironment = record["env"] {
            guard let environment = rawEnvironment as? [String: Any],
                  environment.count <= 4_096 else { return nil }
            for (name, raw) in environment {
                guard matches(name, referencePattern),
                      let value = raw as? String,
                      !value.isEmpty else { return nil }
            }
        }
    case "grant":
        guard Set(record.keys) == ["kind", "payload"],
              let payload = record["payload"],
              validCanonicalJSON(payload, depth: 0) else { return nil }
    default:
        return nil
    }
    return (data, kind)
}

private func declaredRecordKind(_ data: Data) -> String? {
    guard let object = try? JSONSerialization.jsonObject(with: data),
          let record = object as? [String: Any],
          let kind = record["kind"] as? String,
          kind == "api-key" || kind == "grant" else { return nil }
    return kind
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
    let raw = String(cString: directory)
    let home = URL(fileURLWithPath: raw, isDirectory: true).standardizedFileURL
    var metadata = stat()
    var canonical = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard raw.hasPrefix("/"),
          raw.utf8.count <= Int(PATH_MAX),
          lstat(home.path, &metadata) == 0,
          metadata.st_mode & S_IFMT == S_IFDIR,
          metadata.st_uid == geteuid(),
          metadata.st_mode & 0o022 == 0,
          realpath(home.path, &canonical) != nil,
          String(cString: canonical) == home.path else { return nil }
    return home
}

private func metadataCapability() throws -> CredentialPrivateDirectoryCapability {
    guard let home = loginHomeDirectory() else { throw BrokerError.unsafeState }
    do {
        return try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(home: home)
    } catch {
        throw BrokerError.unsafeState
    }
}

private func disableKeychainInteraction() throws {
    guard let handle = dlopen(
        "/System/Library/Frameworks/Security.framework/Security",
        RTLD_LAZY | RTLD_LOCAL
    ), let symbol = dlsym(handle, "SecKeychainSetUserInteractionAllowed") else {
        throw BrokerError.internalFailure
    }
    typealias Setter = @convention(c) (UInt8) -> OSStatus
    let setter = unsafeBitCast(symbol, to: Setter.self)
    guard setter(0) == errSecSuccess else { throw BrokerError.internalFailure }
}

private func baseQuery(service: String = credentialService, account: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

private func nonInteractiveQuery(
    service: String = credentialService,
    account: String
) -> [String: Any] {
    var query = baseQuery(service: service, account: account)
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    return query
}

private func keychainRead(service: String = credentialService, account: String) throws -> Data? {
    var query = nonInteractiveQuery(service: service, account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    var status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecParam {
        query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        result = nil
        status = SecItemCopyMatching(query as CFDictionary, &result)
    }
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = result as? Data else {
        throw keychainError(status)
    }
    return data
}

private func keychainError(_ status: OSStatus) -> CredentialValueStoreError {
    if status == errSecInteractionNotAllowed || status == errSecAuthFailed {
        return .authorizationRequired
    }
    return .status(status)
}

private struct BrokerKeychainStore: CredentialValueStore {
    func read(account: String) throws -> Data? { try keychainRead(account: account) }

    func add(account: String, value: Data) throws {
        var query = baseQuery(account: account)
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
            nonInteractiveQuery(account: account) as CFDictionary,
            replacement as CFDictionary
        )
        if status == errSecParam {
            status = SecItemUpdate(baseQuery(account: account) as CFDictionary, replacement as CFDictionary)
        }
        guard status == errSecSuccess else { throw keychainError(status) }
    }

    func delete(account: String) throws {
        var status = SecItemDelete(nonInteractiveQuery(account: account) as CFDictionary)
        if status == errSecParam { status = SecItemDelete(baseQuery(account: account) as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError(status)
        }
    }
}

private func coordinator() throws -> CredentialTransactionCoordinator {
    do {
        return CredentialTransactionCoordinator(
            stateStore: try CredentialFileStateStore(directoryCapability: metadataCapability()),
            valueStore: BrokerKeychainStore()
        )
    } catch let error as BrokerError {
        throw error
    } catch {
        throw mapError(error)
    }
}

private func mapError(_ error: Error) -> BrokerError {
    if let value = error as? CredentialValueStoreError {
        switch value {
        case .authorizationRequired: return .authorizationRequired
        case .duplicate: return .conflict
        case .status: return .internalFailure
        }
    }
    if let value = error as? CredentialTransactionError {
        switch value {
        case .invalidCredentialKind, .invalidCredentialValue: return .invalidRequest
        case .unsafeState: return .unsafeState
        case .persistenceFailure: return .persistenceFailure
        case .lockTimedOut: return .conflict
        case .verificationFailed: return .verificationFailure
        case .ambiguousRecovery, .recoveryValueMissing, .batchRollbackIncomplete:
            return .recoveryRequired
        case .recoveryNotRequired, .conflict: return .conflict
        }
    }
    return .internalFailure
}

private func enumerateRecordAccounts() throws -> [String] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: credentialService,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnAttributes as String: true,
    ]
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    var status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecParam {
        query.removeValue(forKey: kSecUseAuthenticationContext as String)
        result = nil
        status = SecItemCopyMatching(query as CFDictionary, &result)
    }
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess else { throw mapError(keychainError(status)) }
    let rows: [[String: Any]]
    if let array = result as? [[String: Any]] { rows = array }
    else if let row = result as? [String: Any] { rows = [row] }
    else { throw BrokerError.unsafeState }
    guard rows.count <= 4_096 else { throw BrokerError.unsafeState }
    return try rows.compactMap {
        guard let account = $0[kSecAttrAccount as String] as? String else {
            throw BrokerError.unsafeState
        }
        return decodeRecordAccount(account) == nil ? nil : account
    }.sorted()
}

private func listRecords() throws -> Data {
    let items = try coordinator().listCommittedMetadata()
    let rows = items.compactMap { item -> [String: String]? in
        guard let key = decodeRecordAccount(item.account),
              item.kind == "api-key" || item.kind == "grant" else { return nil }
        return ["key": key, "kind": item.kind]
    }.sorted { left, right in
        guard let leftKey = left["key"], let rightKey = right["key"] else { return false }
        return leftKey < rightKey
    }
    guard let data = try? JSONSerialization.data(withJSONObject: rows),
          data.count <= CredentialBrokerXPCConstants.maximumResponsePayloadBytes else {
        throw BrokerError.unsafeState
    }
    return data
}

private func listRecordAttention() throws -> Data {
    let transaction = try coordinator()
    var items = try transaction.listAttention { data, kind in
        validatedRecord(data)?.kind == kind
    }
    let tracked = Set(items.map(\.account))
    for account in try enumerateRecordAccounts() where !tracked.contains(account) {
        let hasMetadata: Bool
        let metadataUnsafe: Bool
        do {
            hasMetadata = try transaction.metadata(account: account) != nil
            metadataUnsafe = false
        } catch {
            hasMetadata = false
            metadataUnsafe = true
        }
        guard !hasMetadata, let value = try BrokerKeychainStore().read(account: account) else {
            continue
        }
        let kind = declaredRecordKind(value) ?? "unknown"
        let reason: CredentialAttentionReason = validatedRecord(value) != nil
                && !metadataUnsafe && kind != "unknown"
            ? .ambiguous
            : .invalid
        items.append(CredentialAttention(
            account: account,
            kind: kind,
            reason: reason,
            token: CredentialTransactionCoordinator.attentionToken(
                account: account,
                kind: kind,
                reason: reason,
                value: value
            )
        ))
    }
    let rows = items.compactMap { item -> [String: String]? in
        guard let key = decodeRecordAccount(item.account) else { return nil }
        return [
            "key": key,
            "kind": item.kind,
            "reason": item.reason.rawValue,
            "token": item.token,
        ]
    }.sorted { left, right in
        guard let leftKey = left["key"], let rightKey = right["key"] else { return false }
        return leftKey < rightKey
    }
    guard rows.count <= 4_096,
          let data = try? JSONSerialization.data(withJSONObject: rows),
          data.count <= CredentialBrokerXPCConstants.maximumResponsePayloadBytes else {
        throw BrokerError.unsafeState
    }
    return data
}

private func remainingMilliseconds(until deadline: UInt64) -> Int32? {
    let now = DispatchTime.now().uptimeNanoseconds
    guard deadline > now else { return nil }
    let milliseconds = (deadline - now + 999_999) / 1_000_000
    return Int32(min(milliseconds, UInt64(Int32.max)))
}

private func readLine(_ descriptor: Int32, deadline: UInt64, maximumBytes: Int = 64) -> String? {
    var bytes: [UInt8] = []
    while bytes.count <= maximumBytes {
        var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        guard let timeout = remainingMilliseconds(until: deadline),
              poll(&pollDescriptor, 1, timeout) > 0,
              pollDescriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return nil }
        var byte: UInt8 = 0
        let count = read(descriptor, &byte, 1)
        if count < 0, errno == EINTR { continue }
        guard count == 1 else { return nil }
        if byte == 0x0a { return String(bytes: bytes, encoding: .utf8) }
        bytes.append(byte)
    }
    return nil
}

private func readExact(_ descriptor: Int32, count: Int, deadline: UInt64) -> Data? {
    guard count >= 0, count <= CredentialBrokerXPCConstants.maximumCredentialBytes else { return nil }
    if count == 0 { return Data() }
    var result = Data(count: count)
    var offset = 0
    let complete = result.withUnsafeMutableBytes { storage -> Bool in
        guard let baseAddress = storage.baseAddress else { return false }
        while offset < count {
            var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            guard let timeout = remainingMilliseconds(until: deadline),
                  poll(&pollDescriptor, 1, timeout) > 0,
                  pollDescriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return false }
            let amount = read(descriptor, baseAddress.advanced(by: offset), count - offset)
            if amount < 0, errno == EINTR { continue }
            guard amount > 0 else { return false }
            offset += amount
        }
        return true
    }
    return complete ? result : nil
}

private func cleanEOF(_ descriptor: Int32, deadline: UInt64) -> Bool {
    var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
    guard let timeout = remainingMilliseconds(until: deadline),
          poll(&pollDescriptor, 1, timeout) > 0,
          pollDescriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return false }
    var byte: UInt8 = 0
    return read(descriptor, &byte, 1) == 0
}

private func writeAll(_ descriptor: Int32, _ data: Data) throws {
    if data.isEmpty { return }
    var offset = 0
    let complete = data.withUnsafeBytes { storage -> Bool in
        guard let baseAddress = storage.baseAddress else { return false }
        while offset < data.count {
            let amount = write(descriptor, baseAddress.advanced(by: offset), data.count - offset)
            if amount < 0, errno == EINTR { continue }
            guard amount > 0 else { return false }
            offset += amount
        }
        return true
    }
    guard complete else { throw BrokerError.interrupted }
}

private func modifyRecord(
    subject: String,
    transaction: CredentialTransactionCoordinator,
    input: Int32,
    output: Int32,
    deadline: UInt64
) throws {
    let account = recordAccount(subject)
    _ = try transaction.modifyAtomically(account: account) { current in
        if let current, validatedRecord(current) == nil { throw BrokerError.unsafeState }
        try writeAll(output, Data((current.map { "CURRENT \($0.count)\n" } ?? "CURRENT -1\n").utf8))
        if let current { try writeAll(output, current) }
        guard let response = readLine(input, deadline: deadline) else { throw BrokerError.timedOut }
        if response == "UNCHANGED" {
            guard cleanEOF(input, deadline: deadline) else { throw BrokerError.invalidRequest }
            return .unchanged
        }
        let parts = response.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 2,
              parts[0] == "STORE",
              let length = Int(parts[1]),
              let bytes = readExact(input, count: length, deadline: deadline),
              cleanEOF(input, deadline: deadline),
              let validated = validatedRecord(bytes) else { throw BrokerError.invalidRequest }
        return .store(value: validated.data, kind: validated.kind)
    }
    try writeAll(output, Data("COMMITTED\n".utf8))
}

private func backupLoadOrCreate() throws -> Data {
    if let existing = try keychainRead(
        service: backupAuthenticationService,
        account: backupAuthenticationAccount
    ) {
        guard existing.count == 32 else { throw BrokerError.unsafeState }
        return existing
    }
    var key = Data(count: 32)
    let randomStatus: OSStatus = key.withUnsafeMutableBytes { storage in
        guard storage.count == 32, let baseAddress = storage.baseAddress else {
            return errSecParam
        }
        return SecRandomCopyBytes(kSecRandomDefault, storage.count, baseAddress)
    }
    guard randomStatus == errSecSuccess else { throw BrokerError.internalFailure }
    var addition = baseQuery(
        service: backupAuthenticationService,
        account: backupAuthenticationAccount
    )
    addition[kSecValueData as String] = key
    addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(addition as CFDictionary, nil)
    if status == errSecDuplicateItem,
       let raced = try keychainRead(
            service: backupAuthenticationService,
            account: backupAuthenticationAccount
       ), raced.count == 32 { return raced }
    guard status == errSecSuccess,
          try keychainRead(
              service: backupAuthenticationService,
              account: backupAuthenticationAccount
          ) == key else { throw mapError(keychainError(status)) }
    return key
}

private func runAcceptance(nonce: String) throws {
    guard nonce.utf8.count == 36,
          let uuid = UUID(uuidString: nonce),
          uuid.uuidString.lowercased() == nonce else { throw BrokerError.invalidRequest }
    let capability = try metadataCapability()
    let directory = try capability.duplicateDescriptor()
    defer { _ = close(directory) }
    let name = ".credential-broker-acceptance-" + nonce
    let descriptor = name.withCString {
        openat(directory, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    }
    guard descriptor >= 0 else { throw BrokerError.unsafeState }
    var removed = false
    defer {
        _ = close(descriptor)
        if !removed { _ = name.withCString { unlinkat(directory, $0, 0) } }
        _ = fsync(directory)
    }
    var metadata = stat()
    var named = stat()
    guard fstat(descriptor, &metadata) == 0,
          name.withCString({ fstatat(directory, $0, &named, AT_SYMLINK_NOFOLLOW) }) == 0,
          metadata.st_dev == named.st_dev,
          metadata.st_ino == named.st_ino,
          metadata.st_mode & S_IFMT == S_IFREG,
          metadata.st_uid == geteuid(),
          metadata.st_nlink == 1,
          metadata.st_mode & 0o777 == 0o600,
          metadata.st_size == 0,
          fsync(descriptor) == 0,
          fsync(directory) == 0 else { throw BrokerError.persistenceFailure }

    let query = baseQuery(service: acceptanceService, account: nonce)
    var cleanupQuery = query
    let context = LAContext()
    context.interactionNotAllowed = true
    cleanupQuery[kSecUseAuthenticationContext as String] = context
    defer { _ = SecItemDelete(cleanupQuery as CFDictionary) }
    guard try keychainRead(service: acceptanceService, account: nonce) == nil else {
        throw BrokerError.unsafeState
    }
    let value = Data(SHA256.hash(data: Data(nonce.utf8)))
    var addition = query
    addition[kSecValueData as String] = value
    addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    guard SecItemAdd(addition as CFDictionary, nil) == errSecSuccess,
          try keychainRead(service: acceptanceService, account: nonce) == value,
          SecItemDelete(cleanupQuery as CFDictionary) == errSecSuccess,
          try keychainRead(service: acceptanceService, account: nonce) == nil else {
        throw BrokerError.verificationFailure
    }
    guard name.withCString({ unlinkat(directory, $0, 0) }) == 0,
          fsync(directory) == 0 else { throw BrokerError.persistenceFailure }
    removed = true
}

private struct BrokerResult {
    let response: CredentialBrokerXPCResponse
    let payload: Data
}

private func execute(
    request: CredentialBrokerXPCRequest,
    payload: Data,
    input: Int32,
    output: Int32,
    absoluteDeadline: UInt64,
    cancellation: Cancellation
) throws -> BrokerResult {
    try cancellation.check()
    let subjectRequired: Bool
    let recordSubject: Bool
    let payloadRequired: Bool
    switch request.operation {
    case .get, .describe, .set, .unset:
        subjectRequired = true; recordSubject = false; payloadRequired = request.operation == .set
    case .getRecord, .describeRecord, .setRecord, .unsetRecord, .modifyRecordLocked:
        subjectRequired = true; recordSubject = true; payloadRequired = request.operation == .setRecord
    case .listRecords, .listRecordAttention, .backupLoadOrCreate, .acceptance:
        subjectRequired = false; recordSubject = false; payloadRequired = false
    }
    guard subjectRequired ? !request.subject.isEmpty : request.subject.isEmpty,
          request.subject.utf8.count <= 512,
          subjectRequired ? matches(request.subject, recordSubject ? recordPattern : referencePattern) : true,
          payloadRequired ? !payload.isEmpty : payload.isEmpty,
          payload.count <= CredentialBrokerXPCConstants.maximumCredentialBytes,
          request.operation == .acceptance
            ? !request.acceptanceNonce.isEmpty
            : request.acceptanceNonce.isEmpty else { throw BrokerError.invalidRequest }

    let account = subjectRequired
        ? (recordSubject ? recordAccount(request.subject) : "ref:" + request.subject)
        : ""
    let transaction: CredentialTransactionCoordinator?
    if subjectRequired {
        transaction = try coordinator()
    } else {
        transaction = nil
    }
    switch request.operation {
    case .get, .getRecord:
        guard let transaction else { throw BrokerError.internalFailure }
        guard let value = try transaction.readConfiguredValue(account: account) else {
            return BrokerResult(
                response: CredentialBrokerXPCResponse(status: .notFound),
                payload: Data()
            )
        }
        return BrokerResult(response: CredentialBrokerXPCResponse(status: .success), payload: value)
    case .describe, .describeRecord:
        guard let transaction else { throw BrokerError.internalFailure }
        let value = try transaction.readConfiguredValue(account: account)
        if request.operation == .describeRecord, let value {
            guard let record = validatedRecord(value),
                  try transaction.metadata(account: account)?.kind == record.kind else {
                throw BrokerError.unsafeState
            }
        }
        return BrokerResult(
            response: CredentialBrokerXPCResponse(status: .success, configured: value != nil),
            payload: Data()
        )
    case .set, .setRecord:
        guard let transaction else { throw BrokerError.internalFailure }
        let kind: String
        if request.operation == .setRecord {
            guard let record = validatedRecord(payload) else { throw BrokerError.invalidRequest }
            kind = record.kind
        } else {
            kind = "reference"
        }
        try transaction.store(account: account, value: payload, kind: kind)
        return BrokerResult(response: CredentialBrokerXPCResponse(status: .success), payload: Data())
    case .unset, .unsetRecord:
        guard let transaction else { throw BrokerError.internalFailure }
        try transaction.remove(account: account)
        return BrokerResult(response: CredentialBrokerXPCResponse(status: .success), payload: Data())
    case .listRecords:
        return BrokerResult(
            response: CredentialBrokerXPCResponse(status: .success),
            payload: try listRecords()
        )
    case .listRecordAttention:
        return BrokerResult(
            response: CredentialBrokerXPCResponse(status: .success),
            payload: try listRecordAttention()
        )
    case .modifyRecordLocked:
        guard let transaction else { throw BrokerError.internalFailure }
        try modifyRecord(
            subject: request.subject,
            transaction: transaction,
            input: input,
            output: output,
            deadline: absoluteDeadline
        )
        return BrokerResult(response: CredentialBrokerXPCResponse(status: .success), payload: Data())
    case .backupLoadOrCreate:
        return BrokerResult(
            response: CredentialBrokerXPCResponse(status: .success),
            payload: try backupLoadOrCreate()
        )
    case .acceptance:
        try runAcceptance(nonce: request.acceptanceNonce)
        return BrokerResult(response: CredentialBrokerXPCResponse(status: .success), payload: Data())
    }
}

private final class Admission: @unchecked Sendable {
    private let lock = NSLock()
    private var active = false
    func begin() -> Bool { lock.withLock { if active { return false }; active = true; return true } }
    func finish() { lock.withLock { active = false } }
}

private final class BrokerService: NSObject, LocalHarnessCredentialBrokerXPCProtocol {
    private let admission: Admission
    private let cancellation = Cancellation()

    init(admission: Admission) { self.admission = admission }
    func invalidate() { cancellation.cancel(.interrupted) }

    func perform(
        request: NSData,
        payload: NSData,
        input: FileHandle,
        output: FileHandle,
        withReply reply: @escaping (NSData, NSData) -> Void
    ) {
        guard admission.begin() else {
            reply(encode(CredentialBrokerXPCResponse(status: .busy)), NSData())
            return
        }
        defer { admission.finish() }
        var result = BrokerResult(
            response: CredentialBrokerXPCResponse(status: .internalFailure),
            payload: Data()
        )
        do {
            try disableKeychainInteraction()
            guard request.length > 0,
                  request.length <= CredentialBrokerXPCConstants.maximumRequestBytes,
                  payload.length <= CredentialBrokerXPCConstants.maximumCredentialBytes,
                  let decoded = CredentialBrokerXPCSchema.decodeRequest(request as Data),
                  decoded.version == CredentialBrokerXPCConstants.protocolVersion,
                  decoded.deadlineNanoseconds >= CredentialBrokerXPCConstants.minimumDeadlineNanoseconds,
                  decoded.deadlineNanoseconds <= CredentialBrokerXPCConstants.maximumDeadlineNanoseconds else {
                throw BrokerError.invalidRequest
            }
            let (deadlineValue, overflow) = DispatchTime.now().uptimeNanoseconds
                .addingReportingOverflow(decoded.deadlineNanoseconds)
            let (hardStopValue, hardStopOverflow) = deadlineValue.addingReportingOverflow(250_000_000)
            guard !overflow, !hardStopOverflow else { throw BrokerError.invalidRequest }
            let timeout = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
            let hardStop = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
            let gate = HardStopGate()
            timeout.schedule(deadline: DispatchTime(uptimeNanoseconds: deadlineValue))
            timeout.setEventHandler { self.cancellation.cancel(.timedOut) }
            hardStop.schedule(deadline: DispatchTime(uptimeNanoseconds: hardStopValue))
            hardStop.setEventHandler { gate.terminateIfActive() }
            timeout.resume(); hardStop.resume()
            defer { gate.deactivate(); timeout.cancel(); hardStop.cancel() }
            result = try execute(
                request: decoded,
                payload: payload as Data,
                input: input.fileDescriptor,
                output: output.fileDescriptor,
                absoluteDeadline: deadlineValue,
                cancellation: cancellation
            )
            try cancellation.check()
            guard result.payload.count <= CredentialBrokerXPCConstants.maximumResponsePayloadBytes else {
                throw BrokerError.unsafeState
            }
        } catch let error as BrokerError {
            result = BrokerResult(
                response: CredentialBrokerXPCResponse(status: error.status),
                payload: Data()
            )
        } catch {
            result = BrokerResult(
                response: CredentialBrokerXPCResponse(status: mapError(error).status),
                payload: Data()
            )
        }
        reply(encode(result.response), result.payload as NSData)
    }

    private func encode(_ response: CredentialBrokerXPCResponse) -> NSData {
        ((try? CredentialBrokerXPCSchema.encode(response))
            ?? Data(#"{"configured":false,"status":"internalFailure","version":1}"#.utf8)) as NSData
    }
}

private final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let helperRequirement: String
    private let admission = Admission()

    override init() {
        do {
            let serviceBundle = Bundle.main.bundleURL.standardizedFileURL
            let xpcDirectory = serviceBundle.deletingLastPathComponent()
            let contents = xpcDirectory.deletingLastPathComponent()
            let application = contents.deletingLastPathComponent()
            let helper = contents.appendingPathComponent("MacOS", isDirectory: true)
                .appendingPathComponent("LocalHarnessCredentialHelper", isDirectory: false)
            guard Bundle.main.bundleIdentifier == CredentialBrokerXPCConstants.serviceName,
                  serviceBundle.lastPathComponent == CredentialBrokerXPCConstants.serviceBundleName,
                  xpcDirectory.lastPathComponent == "XPCServices",
                  contents.lastPathComponent == "Contents",
                  application.pathExtension == "app",
                  Bundle(url: application)?.bundleIdentifier == applicationBundleIdentifier else {
                failClosedStartup()
            }
            let serviceIdentity = try CodeIdentity.inspect(serviceBundle, nested: false)
            let helperIdentity = try CodeIdentity.inspect(helper, nested: false)
            guard serviceIdentity.identifier == CredentialBrokerXPCConstants.codeIdentifier,
                  helperIdentity.identifier == CredentialBrokerXPCConstants.codeIdentifier,
                  serviceIdentity.designatedRequirement == helperIdentity.designatedRequirement else {
                failClosedStartup()
            }
            helperRequirement = helperIdentity.exactRequirement
        } catch {
            failClosedStartup()
        }
        super.init()
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.setCodeSigningRequirement(helperRequirement)
        let service = BrokerService(admission: admission)
        connection.exportedInterface = NSXPCInterface(
            with: LocalHarnessCredentialBrokerXPCProtocol.self
        )
        connection.exportedObject = service
        connection.interruptionHandler = { [weak service] in service?.invalidate() }
        connection.invalidationHandler = { [weak service] in service?.invalidate() }
        connection.resume()
        return true
    }
}

private let delegate = ListenerDelegate()
private let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
