import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import LocalHarnessCredentialSecurity
import Security

private let service = "app.localharness.credentials"
private let backupAuthenticationService = "com.angadjairath.localharness.backup-authentication"
private let backupAuthenticationAccount = "state-backup-manifest-v2"
private let referencePattern = try? NSRegularExpression(pattern: #"^[A-Za-z_][A-Za-z0-9_]*$"#)
private let recordPattern = try? NSRegularExpression(pattern: #"^[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+$"#)
private let maxValueBytes = 1_048_576
private let telemetryFileName = "performance-telemetry.json"
private let telemetryLockName = ".performance-telemetry.lock"
private let authorizationRequiredExitStatus: Int32 = 5
private let recoveryRequiredExitStatus: Int32 = 6
private let transactionBusyExitStatus: Int32 = 7
private let unsafeStateExitStatus: Int32 = 8
private let persistenceFailureExitStatus: Int32 = 9
private let verificationFailureExitStatus: Int32 = 10
private let credentialRecordProtocolFailureExitStatus: Int32 = 11
private let metadataDirectoryName = "CredentialMetadata"
private let applicationBundleIdentifier = "com.angadjairath.localharness"

private func fail(_ message: String, status: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data("Credential helper: \(message)\n".utf8))
    exit(status)
}

/// Foreground authorization/repair is intentionally the only credential path
/// which may display Keychain UI. The DSH runtime can execute the helper for
/// unattended broker commands, so a command name alone is not authority for a
/// foreground mutation. Require the immediate parent to be the exact running
/// Mach-O from the same signed packaged app before any Keychain or metadata
/// object is opened.
private func exactPackagedApplicationIsImmediateParent() -> Bool {
    let helper = URL(fileURLWithPath: CommandLine.arguments[0], isDirectory: false)
        .standardizedFileURL
    let macOSDirectory = helper.deletingLastPathComponent()
    let contents = macOSDirectory.deletingLastPathComponent()
    let application = contents.deletingLastPathComponent()

    #if DEBUG
    if application.pathExtension != "app" {
        // Source-tree transaction tests never ship and retain their existing
        // direct helper seam. A packaged helper, including a debug package,
        // must satisfy the production running-code boundary below.
        return true
    }
    #endif

    let applicationExecutable = macOSDirectory.appendingPathComponent(
        "LocalHarness",
        isDirectory: false
    ).standardizedFileURL
    guard helper.path.hasPrefix("/"),
          helper.lastPathComponent == "LocalHarnessCredentialHelper",
          helper.path == helper.resolvingSymlinksInPath().standardizedFileURL.path,
          macOSDirectory.lastPathComponent == "MacOS",
          contents.lastPathComponent == "Contents",
          application.pathExtension == "app",
          application.path == application.resolvingSymlinksInPath().standardizedFileURL.path,
          Bundle(url: application)?.bundleIdentifier == applicationBundleIdentifier,
          applicationExecutable.path
            == applicationExecutable.resolvingSymlinksInPath().standardizedFileURL.path else {
        return false
    }

    var executableBefore = stat()
    guard lstat(applicationExecutable.path, &executableBefore) == 0,
          executableBefore.st_mode & S_IFMT == S_IFREG,
          executableBefore.st_nlink == 1,
          executableBefore.st_uid == geteuid() || executableBefore.st_uid == 0,
          executableBefore.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID) == 0 else {
        return false
    }
    var staticCode: SecStaticCode?
    let staticFlags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode
    )
    guard SecStaticCodeCreateWithPath(application as CFURL, [], &staticCode) == errSecSuccess,
          let staticCode,
          SecStaticCodeCheckValidity(staticCode, staticFlags, nil) == errSecSuccess else {
        return false
    }
    var signingInformation: CFDictionary?
    guard SecCodeCopySigningInformation(
        staticCode,
        SecCSFlags(rawValue: kSecCSSigningInformation),
        &signingInformation
    ) == errSecSuccess,
          let values = signingInformation as? [String: Any],
          values[kSecCodeInfoIdentifier as String] as? String == applicationBundleIdentifier,
          let codeDirectoryHash = values[kSecCodeInfoUnique as String] as? Data,
          !codeDirectoryHash.isEmpty,
          codeDirectoryHash.count <= 64 else {
        return false
    }
    let hash = codeDirectoryHash.map { String(format: "%02x", $0) }.joined()
    var exactRequirement: SecRequirement?
    let requirementText = "identifier \"\(applicationBundleIdentifier)\" and cdhash H\"\(hash)\""
    guard SecRequirementCreateWithString(
        requirementText as CFString,
        [],
        &exactRequirement
    ) == errSecSuccess,
          let exactRequirement else { return false }

    let parent = getppid()
    guard parent > 1 else { return false }
    var pathBuffer = [CChar](repeating: 0, count: 4_096)
    let pathLength = proc_pidpath(parent, &pathBuffer, UInt32(pathBuffer.count))
    guard pathLength > 0,
          URL(fileURLWithPath: String(cString: pathBuffer), isDirectory: false)
            .resolvingSymlinksInPath().standardizedFileURL == applicationExecutable else {
        return false
    }
    let attributes = [
        kSecGuestAttributePid as String: NSNumber(value: parent),
    ] as CFDictionary
    var runningCode: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &runningCode) == errSecSuccess,
          let runningCode,
          SecCodeCheckValidity(
            runningCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            exactRequirement
          ) == errSecSuccess,
          getppid() == parent else { return false }

    var executableAfter = stat()
    return lstat(applicationExecutable.path, &executableAfter) == 0
        && executableAfter.st_dev == executableBefore.st_dev
        && executableAfter.st_ino == executableBefore.st_ino
        && executableAfter.st_size == executableBefore.st_size
        && executableAfter.st_mtimespec.tv_sec == executableBefore.st_mtimespec.tv_sec
        && executableAfter.st_mtimespec.tv_nsec == executableBefore.st_mtimespec.tv_nsec
        && SecStaticCodeCheckValidity(staticCode, staticFlags, exactRequirement) == errSecSuccess
}

private func matches(_ value: String, expression: NSRegularExpression?) -> Bool {
    guard let expression else { return false }
    let range = NSRange(value.startIndex..., in: value)
    return expression.firstMatch(in: value, range: range)?.range == range
}

/// Reads exactly one bounded credential payload from stdin. Reading one byte
/// beyond the admitted limit distinguishes a valid maximum-sized value from an
/// oversized stream without ever accumulating attacker-controlled input.
private func readBoundedCredentialInput() -> Data {
    var result = Data()
    result.reserveCapacity(min(maxValueBytes, 64 * 1_024))
    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    while true {
        let remaining = maxValueBytes - result.count
        let requested = min(buffer.count, remaining + 1)
        let count = buffer.withUnsafeMutableBytes { storage -> Int in
            guard let baseAddress = storage.baseAddress else { return -1 }
            return Darwin.read(STDIN_FILENO, baseAddress, requested)
        }
        if count == 0 { return result }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { fail("credential input could not be read") }
        guard count <= remaining else {
            fail("credential input exceeds the maximum size")
        }
        result.append(contentsOf: buffer.prefix(count))
    }
}

private func validatedRecord(_ data: Data) -> (data: Data, kind: String)? {
    guard !data.isEmpty, data.count <= maxValueBytes,
          let object = try? JSONSerialization.jsonObject(with: data),
          let record = object as? [String: Any],
          let kind = record["kind"] as? String else { return nil }
    switch kind {
    case "api-key":
        guard Set(record.keys).isSubset(of: ["kind", "key", "env"]) else { return nil }
        if let key = record["key"] {
            guard let key = key as? String, !key.isEmpty else { return nil }
        }
        if let environment = record["env"] {
            guard let environment = environment as? [String: Any] else { return nil }
            for (name, value) in environment {
                guard matches(name, expression: referencePattern),
                      let value = value as? String, !value.isEmpty else { return nil }
            }
        }
    case "grant":
        guard Set(record.keys) == ["kind", "payload"], let payload = record["payload"],
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

private func validCanonicalJSON(_ value: Any, depth: Int) -> Bool {
    guard depth <= 64 else { return false }
    if value is NSNull || value is String || value is Bool { return true }
    if let number = value as? NSNumber {
        return number.doubleValue.isFinite
    }
    if let array = value as? [Any] {
        return array.allSatisfy { validCanonicalJSON($0, depth: depth + 1) }
    }
    if let object = value as? [String: Any] {
        return object.values.allSatisfy { validCanonicalJSON($0, depth: depth + 1) }
    }
    return false
}

private func remainingRecordProtocolMilliseconds(until deadline: UInt64) -> Int32? {
    let now = DispatchTime.now().uptimeNanoseconds
    guard deadline > now else { return nil }
    let milliseconds = (deadline - now + 999_999) / 1_000_000
    return Int32(min(milliseconds, UInt64(Int32.max)))
}

private func readRecordProtocolLine(deadline: UInt64, maximumBytes: Int = 64) -> String? {
    var bytes: [UInt8] = []
    while bytes.count <= maximumBytes {
        var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        guard let timeout = remainingRecordProtocolMilliseconds(until: deadline) else { return nil }
        let ready = Darwin.poll(&descriptor, 1, timeout)
        guard ready > 0, descriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return nil }
        var byte: UInt8 = 0
        let count = Darwin.read(STDIN_FILENO, &byte, 1)
        if count < 0, errno == EINTR { continue }
        guard count == 1 else { return nil }
        if byte == 0x0a { return String(bytes: bytes, encoding: .utf8) }
        bytes.append(byte)
    }
    return nil
}

private func readExactRecordProtocolBytes(_ count: Int, deadline: UInt64) -> Data? {
    guard count >= 0, count <= maxValueBytes else { return nil }
    if count == 0 { return Data() }
    var result = Data(count: count)
    var offset = 0
    let complete = result.withUnsafeMutableBytes { storage -> Bool in
        guard let baseAddress = storage.baseAddress else { return false }
        while offset < count {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            guard let timeout = remainingRecordProtocolMilliseconds(until: deadline) else { return false }
            let ready = Darwin.poll(&descriptor, 1, timeout)
            guard ready > 0, descriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return false }
            let readCount = Darwin.read(STDIN_FILENO, baseAddress.advanced(by: offset), count - offset)
            if readCount < 0, errno == EINTR { continue }
            guard readCount > 0 else { return false }
            offset += readCount
        }
        return true
    }
    return complete ? result : nil
}

private func recordProtocolReachedCleanEOF(deadline: UInt64) -> Bool {
    var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
    guard let timeout = remainingRecordProtocolMilliseconds(until: deadline),
          Darwin.poll(&descriptor, 1, timeout) > 0,
          descriptor.revents & Int16(POLLIN | POLLHUP) != 0 else { return false }
    var byte: UInt8 = 0
    return Darwin.read(STDIN_FILENO, &byte, 1) == 0
}

private func account(for command: String, subject: String) -> String {
    if command.contains("record") {
        guard subject.count <= 512, matches(subject, expression: recordPattern) else { fail("invalid credential record key") }
        return "record:" + Data(subject.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    guard matches(subject, expression: referencePattern) else { fail("invalid credential reference") }
    return "ref:" + subject
}

private func baseQuery(_ account: String) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
}

/// Every unattended Keychain operation must fail closed instead of presenting
/// an authorization dialog from a background helper. A user can then repair
/// the exact credential from Fulmar's provider UI without an agent turn
/// hanging behind an unseen password prompt.
private func nonInteractiveQuery(_ account: String) -> [String: Any] {
    var query = baseQuery(account)
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    return query
}

private func backupAuthenticationBaseQuery() -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: backupAuthenticationService,
        kSecAttrAccount as String: backupAuthenticationAccount
    ]
}

private func nonInteractiveBackupAuthenticationQuery() -> [String: Any] {
    var query = backupAuthenticationBaseQuery()
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    return query
}

private func failBackupAuthenticationKeychain(_ operation: String, status: OSStatus) -> Never {
    if status == errSecInteractionNotAllowed || status == errSecAuthFailed || status == errSecUserCanceled {
        fail("Backup authentication Keychain authorization is required", status: authorizationRequiredExitStatus)
    }
    fail("Backup authentication Keychain \(operation) failed (\(status))")
}

private func lookupBackupAuthenticationKey(nonInteractive: Bool) -> (status: OSStatus, data: Data?) {
    var query = nonInteractive
        ? nonInteractiveBackupAuthenticationQuery()
        : backupAuthenticationBaseQuery()
    if !nonInteractive {
        // This path is reachable only from the deliberate foreground repair
        // action. It reads the exact existing key and never creates, replaces,
        // or deletes a Keychain item.
        let context = LAContext()
        context.localizedReason = "Allow Fulmar to authenticate its existing local backups."
        query[kSecUseAuthenticationContext as String] = context
    }
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    var status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecParam {
        // Legacy login-Keychain generic-password items can reject the modern
        // LAContext query key outright. On unattended calls this compatibility
        // retry is safe only after SecKeychainSetUserInteractionAllowed(0) has
        // succeeded. On the other path it follows the user's explicit native
        // Authorize Existing Key action and may present the expected prompt.
        query = backupAuthenticationBaseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        result = nil
        status = SecItemCopyMatching(query as CFDictionary, &result)
    }
    return (status, result as? Data)
}

private func runBackupAuthenticationKeyLoadOrCreate() -> Never {
    let existing = lookupBackupAuthenticationKey(nonInteractive: true)
    if existing.status == errSecSuccess {
        guard let data = existing.data, data.count == 32 else {
            fail("Backup authentication key has an invalid length")
        }
        FileHandle.standardOutput.write(data)
        exit(0)
    }
    if existing.status != errSecItemNotFound {
        failBackupAuthenticationKeychain("read", status: existing.status)
    }

    var key = Data(count: 32)
    let randomStatus: OSStatus = key.withUnsafeMutableBytes { storage in
        guard storage.count == 32, let baseAddress = storage.baseAddress else {
            return errSecParam
        }
        return SecRandomCopyBytes(kSecRandomDefault, storage.count, baseAddress)
    }
    guard randomStatus == errSecSuccess else {
        fail("Backup authentication key generation failed")
    }
    var addition = nonInteractiveBackupAuthenticationQuery()
    addition[kSecValueData as String] = key
    addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    var added = SecItemAdd(addition as CFDictionary, nil)
    if added == errSecParam {
        // See the legacy-query compatibility note above. Process-wide Keychain
        // UI remains disabled for this exact helper invocation.
        addition = backupAuthenticationBaseQuery()
        addition[kSecValueData as String] = key
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        added = SecItemAdd(addition as CFDictionary, nil)
    }
    if added == errSecDuplicateItem {
        // Another process won the create race. Read and return only that exact
        // winner; never replace or delete it, including when its ACL is owned
        // by a different signing identity.
        let raced = lookupBackupAuthenticationKey(nonInteractive: true)
        guard raced.status == errSecSuccess else {
            failBackupAuthenticationKeychain("duplicate-race read", status: raced.status)
        }
        guard let data = raced.data, data.count == 32 else {
            fail("Backup authentication key has an invalid length")
        }
        FileHandle.standardOutput.write(data)
        exit(0)
    }
    guard added == errSecSuccess else {
        failBackupAuthenticationKeychain("write", status: added)
    }
    let verified = lookupBackupAuthenticationKey(nonInteractive: true)
    guard verified.status == errSecSuccess else {
        failBackupAuthenticationKeychain("write verification", status: verified.status)
    }
    guard verified.data == key else {
        fail("Backup authentication key write verification failed")
    }
    FileHandle.standardOutput.write(key)
    exit(0)
}

private func runBackupAuthenticationKeyForegroundAuthorization() -> Never {
    let existing = lookupBackupAuthenticationKey(nonInteractive: false)
    if existing.status == errSecItemNotFound { exit(3) }
    guard existing.status == errSecSuccess else {
        failBackupAuthenticationKeychain("foreground authorization", status: existing.status)
    }
    guard let data = existing.data, data.count == 32 else {
        fail("Backup authentication key has an invalid length")
    }
    FileHandle.standardOutput.write(data)
    exit(0)
}

private func credentialMetadataDirectory() -> CredentialPrivateDirectoryCapability {
    guard let home = ProcessInfo.processInfo.environment["HOME"], home.hasPrefix("/"), home.utf8.count <= 1_024 else {
        fail("HOME is unavailable")
    }
    let homeURL = URL(fileURLWithPath: home, isDirectory: true).standardizedFileURL
    guard homeURL.path == home, homeURL.resolvingSymlinksInPath().standardizedFileURL.path == home else {
        fail("HOME is unsafe")
    }
    do {
        return try CredentialPrivateDirectory.prepareMetadataDirectoryCapability(
            home: homeURL,
            metadataName: metadataDirectoryName
        )
    } catch {
        fail("credential metadata directory is unsafe")
    }
}

/// Agent turns and background catalog refreshes must never summon a system
/// authorization dialog. A credential whose ACL does not admit this exact
/// signed helper is reported to the native provider UI instead of blocking an
/// inference subprocess behind an unseen password prompt.
private func failKeychain(_ operation: String, status: OSStatus) -> Never {
    if status == errSecInteractionNotAllowed || status == errSecAuthFailed {
        fail("Keychain authorization is required", status: authorizationRequiredExitStatus)
    }
    fail("Keychain \(operation) failed (\(status))")
}

private func lookup(account: String) -> (status: OSStatus, data: Data?) {
    var query = nonInteractiveQuery(account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    var status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecParam {
        // Some legacy login-Keychain items reject the LAContext query key.
        // This fallback is reached only after process-wide Keychain UI has
        // been disabled for the ordinary helper path.
        query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        result = nil
        status = SecItemCopyMatching(query as CFDictionary, &result)
    }
    return (status, result as? Data)
}

private struct SystemKeychainCredentialValueStore: CredentialValueStore {
    func read(account: String) throws -> Data? {
        let result = lookup(account: account)
        if result.status == errSecItemNotFound { return nil }
        guard result.status == errSecSuccess, let data = result.data else {
            throw Self.error(for: result.status)
        }
        return data
    }

    func add(account: String, value: Data) throws {
        var addition = baseQuery(account)
        addition[kSecValueData as String] = value
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(addition as CFDictionary, nil)
        if status == errSecDuplicateItem { throw CredentialValueStoreError.duplicate }
        guard status == errSecSuccess else { throw Self.error(for: status) }
    }

    func replace(account: String, value: Data) throws {
        let replacement: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(nonInteractiveQuery(account) as CFDictionary, replacement as CFDictionary)
        if status == errSecParam {
            status = SecItemUpdate(baseQuery(account) as CFDictionary, replacement as CFDictionary)
        }
        guard status == errSecSuccess else { throw Self.error(for: status) }
    }

    func delete(account: String) throws {
        var status = SecItemDelete(nonInteractiveQuery(account) as CFDictionary)
        if status == errSecParam { status = SecItemDelete(baseQuery(account) as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(for: status)
        }
    }

    private static func error(for status: OSStatus) -> CredentialValueStoreError {
        if status == errSecInteractionNotAllowed || status == errSecAuthFailed {
            return .authorizationRequired
        }
        return .status(status)
    }
}

/// Used only by an explicit native foreground repair action dispatched before
/// process-wide Keychain UI suppression. One LAContext is retained for the
/// exact bounded helper lifetime; no credential bytes are written to stdout.
private final class ForegroundSystemKeychainCredentialValueStore: CredentialValueStore {
    private let context = LAContext()

    init() {
        context.localizedReason = "Allow Fulmar to repair this exact existing provider credential."
    }

    func read(account: String) throws -> Data? {
        var query = foregroundQuery(account)
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
        guard status == errSecSuccess, let data = result as? Data else {
            throw Self.error(for: status)
        }
        return data
    }

    func add(account: String, value: Data) throws {
        var addition = baseQuery(account)
        addition[kSecValueData as String] = value
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(addition as CFDictionary, nil)
        if status == errSecDuplicateItem { throw CredentialValueStoreError.duplicate }
        guard status == errSecSuccess else { throw Self.error(for: status) }
    }

    func replace(account: String, value: Data) throws {
        let replacement: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(
            foregroundQuery(account) as CFDictionary,
            replacement as CFDictionary
        )
        if status == errSecParam {
            status = SecItemUpdate(baseQuery(account) as CFDictionary, replacement as CFDictionary)
        }
        guard status == errSecSuccess else { throw Self.error(for: status) }
    }

    func delete(account: String) throws {
        var status = SecItemDelete(foregroundQuery(account) as CFDictionary)
        if status == errSecParam { status = SecItemDelete(baseQuery(account) as CFDictionary) }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(for: status)
        }
    }

    private func foregroundQuery(_ account: String) -> [String: Any] {
        var query = baseQuery(account)
        query[kSecUseAuthenticationContext as String] = context
        return query
    }

    private static func error(for status: OSStatus) -> CredentialValueStoreError {
        if status == errSecInteractionNotAllowed || status == errSecAuthFailed
            || status == errSecUserCanceled {
            return .authorizationRequired
        }
        return .status(status)
    }
}

private func failCredentialTransaction(_ error: Error, operation: String) -> Never {
    if let valueError = error as? CredentialValueStoreError {
        switch valueError {
        case .authorizationRequired:
            fail("Keychain authorization is required", status: authorizationRequiredExitStatus)
        case .status(let status):
            failKeychain(operation, status: status)
        case .duplicate:
            fail("Keychain \(operation) encountered an unresolved duplicate item")
        }
    }
    if let transactionError = error as? CredentialTransactionError {
        switch transactionError {
        case .invalidCredentialKind:
            fail("credential kind is invalid")
        case .invalidCredentialValue:
            fail("credential must contain 1 to \(maxValueBytes) bytes")
        case .unsafeState:
            fail("credential state is unsafe", status: unsafeStateExitStatus)
        case .persistenceFailure:
            fail("credential state is unavailable", status: persistenceFailureExitStatus)
        case .lockTimedOut:
            fail("credential transaction is busy", status: transactionBusyExitStatus)
        case .verificationFailed:
            fail("Keychain \(operation) verification failed", status: verificationFailureExitStatus)
        case .ambiguousRecovery:
            fail("credential transaction recovery requires attention", status: recoveryRequiredExitStatus)
        case .recoveryNotRequired:
            fail("credential transaction recovery is no longer required", status: verificationFailureExitStatus)
        case .recoveryValueMissing:
            fail("credential transaction recovery value is unavailable", status: recoveryRequiredExitStatus)
        case .conflict:
            fail("credential record changed before commit", status: 11)
        case .batchRollbackIncomplete:
            fail("credential migration rollback requires recovery", status: recoveryRequiredExitStatus)
        }
    }
    fail("credential \(operation) failed")
}

private func credentialCoordinator(
    valueStore: any CredentialValueStore = SystemKeychainCredentialValueStore()
) -> CredentialTransactionCoordinator {
    do {
        let state = try CredentialFileStateStore(
            directoryCapability: credentialMetadataDirectory()
        )
        return CredentialTransactionCoordinator(
            stateStore: state,
            valueStore: valueStore
        )
    } catch {
        failCredentialTransaction(error, operation: "state initialization")
    }
}

private func runForegroundCredentialOperation(command: String, subject: String) -> Never {
    let keychainAccount = account(for: command, subject: subject)
    let valueStore = ForegroundSystemKeychainCredentialValueStore()
    let coordinator = credentialCoordinator(
        valueStore: valueStore
    )
    do {
        switch command {
        case "authorize":
            guard try coordinator.readConfiguredValue(account: keychainAccount) != nil else { exit(3) }
        case "repair-adopt":
            try coordinator.repairAdoptingCurrentValue(account: keychainAccount, kind: "reference")
        case "repair-replace":
            try coordinator.repairReplacingCurrentValue(
                account: keychainAccount,
                value: readBoundedCredentialInput(),
                kind: "reference"
            )
        case "repair-remove":
            try coordinator.repairRemovingCurrentValue(account: keychainAccount, kind: "reference")
        case "authorize-record":
            guard let value = try coordinator.readConfiguredValue(account: keychainAccount) else { exit(3) }
            guard let record = validatedRecord(value),
                  try coordinator.metadata(account: keychainAccount)?.kind == record.kind else {
                fail("credential record is invalid", status: unsafeStateExitStatus)
            }
        case "repair-adopt-record":
            do {
                try coordinator.repairAdoptingCurrentRecord(account: keychainAccount) { data in
                    validatedRecord(data)?.kind
                }
            } catch CredentialTransactionError.recoveryNotRequired {
                try coordinator.adoptUntrackedCurrentRecord(account: keychainAccount) { data in
                    validatedRecord(data)?.kind
                }
            }
        case "repair-remove-record":
            guard let token = String(data: readBoundedCredentialInput(), encoding: .utf8) else {
                fail("credential attention token is invalid", status: unsafeStateExitStatus)
            }
            try coordinator.repairRemovingCurrentRecord(
                account: keychainAccount,
                expectedToken: token,
                validateKind: { validatedRecord($0)?.kind },
                declaredKind: { declaredRecordKind($0) }
            )
        default:
            fail("unknown foreground credential command")
        }
        FileHandle.standardOutput.write(Data("OK\n".utf8))
        exit(0)
    } catch {
        failCredentialTransaction(error, operation: "foreground repair")
    }
}

private func enumerateKeychainRecordAccounts() throws -> [String] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecMatchLimit as String: kSecMatchLimitAll,
        kSecReturnAttributes as String: true
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
    guard status == errSecSuccess else { throw CredentialValueStoreError.status(status) }
    let rows: [[String: Any]]
    if let array = result as? [[String: Any]] { rows = array }
    else if let row = result as? [String: Any] { rows = [row] }
    else { throw CredentialTransactionError.unsafeState("Keychain record catalogue is invalid") }
    guard rows.count <= 4_096 else {
        throw CredentialTransactionError.unsafeState("Keychain record catalogue exceeds its bound")
    }
    return try rows.compactMap { row in
        guard let account = row[kSecAttrAccount as String] as? String else {
            throw CredentialTransactionError.unsafeState("Keychain record account is invalid")
        }
        return decodeRecordAccount(account) == nil ? nil : account
    }.sorted()
}

private func listRecordAttention() -> Data {
    do {
        let coordinator = credentialCoordinator()
        var items = try coordinator.listAttention { data, metadataKind in
            guard let record = validatedRecord(data) else { return false }
            return record.kind == metadataKind
        }
        let tracked = Set(items.map(\.account))
        let valueStore = SystemKeychainCredentialValueStore()
        for account in try enumerateKeychainRecordAccounts() where !tracked.contains(account) {
            let hasMetadata: Bool
            let metadataUnsafe: Bool
            do {
                hasMetadata = try coordinator.metadata(account: account) != nil
                metadataUnsafe = false
            } catch {
                hasMetadata = false
                metadataUnsafe = true
            }
            guard !hasMetadata, let value = try valueStore.read(account: account) else { continue }
            // A metadata-less record with malformed bytes or an unknown schema must
            // remain visible to recovery. `unknown` is presentation-only: it is
            // never eligible for adoption/authorization or persisted as metadata.
            let kind = declaredRecordKind(value) ?? "unknown"
            let valid = validatedRecord(value) != nil
            let reason: CredentialAttentionReason = valid && !metadataUnsafe && kind != "unknown"
                ? .ambiguous : .invalid
            items.append(CredentialAttention(
                account: account,
                kind: kind,
                reason: reason,
                token: CredentialTransactionCoordinator.attentionToken(
                    account: account, kind: kind, reason: reason, value: value
                )
            ))
        }
        let metadata: [[String: String]] = items.compactMap { item in
            guard let key = decodeRecordAccount(item.account) else { return nil }
            return ["key": key, "kind": item.kind, "reason": item.reason.rawValue, "token": item.token]
        }.sorted { ($0["key"] ?? "") < ($1["key"] ?? "") }
        guard metadata.count <= 4_096,
              let encoded = try? JSONSerialization.data(withJSONObject: metadata),
              encoded.count <= 3 * 1_024 * 1_024 else {
            fail("record attention catalogue exceeds its transport bound", status: unsafeStateExitStatus)
        }
        return encoded
    } catch {
        failCredentialTransaction(error, operation: "record attention listing")
    }
}

private func decodeRecordAccount(_ account: String) -> String? {
    guard account.hasPrefix("record:") else { return nil }
    var encoded = String(account.dropFirst("record:".count)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while encoded.count % 4 != 0 { encoded.append("=") }
    guard let data = Data(base64Encoded: encoded), let key = String(data: data, encoding: .utf8), matches(key, expression: recordPattern) else { return nil }
    return key
}

private func listRecordMetadata() -> Data {
    do {
        let items = try credentialCoordinator().listCommittedMetadata()
        var metadata: [[String: String]] = []
        for item in items {
            guard let key = decodeRecordAccount(item.account),
                  item.kind == "api-key" || item.kind == "grant" else { continue }
            metadata.append(["key": key, "kind": item.kind])
        }
        return (try? JSONSerialization.data(
            withJSONObject: metadata.sorted { ($0["key"] ?? "") < ($1["key"] ?? "") }
        )) ?? Data("[]".utf8)
    } catch {
        failCredentialTransaction(error, operation: "metadata listing")
    }
}

private func runLockedRecordModification(subject: String) -> Never {
    let keychainAccount = account(for: "modify-record-locked", subject: subject)
    do {
        let result = try credentialCoordinator().modifyAtomically(account: keychainAccount) { current in
            if let current, validatedRecord(current) == nil {
                fail("stored credential record is invalid", status: unsafeStateExitStatus)
            }
            let header = current.map { "CURRENT \($0.count)\n" } ?? "CURRENT -1\n"
            FileHandle.standardOutput.write(Data(header.utf8))
            if let current { FileHandle.standardOutput.write(current) }
            let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
            guard let response = readRecordProtocolLine(deadline: deadline) else {
                fail("record modification protocol timed out or closed", status: credentialRecordProtocolFailureExitStatus)
            }
            if response == "UNCHANGED" {
                guard recordProtocolReachedCleanEOF(deadline: deadline) else {
                    fail("invalid unchanged record protocol payload", status: credentialRecordProtocolFailureExitStatus)
                }
                return .unchanged
            }
            let parts = response.split(separator: " ", omittingEmptySubsequences: false)
            guard parts.count == 2, parts[0] == "STORE", let length = Int(parts[1]),
                  let bytes = readExactRecordProtocolBytes(length, deadline: deadline),
                  recordProtocolReachedCleanEOF(deadline: deadline),
                  let validated = validatedRecord(bytes) else {
                fail("invalid record modification protocol payload", status: credentialRecordProtocolFailureExitStatus)
            }
            return .store(value: validated.data, kind: validated.kind)
        }
        FileHandle.standardOutput.write(Data("COMMITTED\n".utf8))
        if let result { FileHandle.standardOutput.write(result) }
        exit(0)
    } catch {
        failCredentialTransaction(error, operation: "record modification")
    }
}

private func securePrivateDirectory(_ path: String, exactName: String) -> Bool {
    let url = URL(fileURLWithPath: path, isDirectory: true)
    let standardized = url.standardizedFileURL.path
    let resolved = url.resolvingSymlinksInPath().standardizedFileURL.path
    // Foundation presents Apple's trusted `/private/tmp` system directory as
    // `/tmp`. Admit only that exact spelling transition; any other symlinked
    // parent still makes `resolved` differ from the expected standardized path.
    let trustedPrivateTemporaryAlias = path.hasPrefix("/private/tmp/")
        && standardized == "/tmp/" + path.dropFirst("/private/tmp/".count)
        && resolved == standardized
    guard ((path == standardized && path == resolved) || trustedPrivateTemporaryAlias),
          url.lastPathComponent == exactName else { return false }
    var metadata = stat()
    return lstat(path, &metadata) == 0
        && metadata.st_mode & S_IFMT == S_IFDIR
        && metadata.st_uid == geteuid()
        && metadata.st_mode & 0o777 == 0o700
}

private func runTelemetryLock(applicationSupportPath: String, telemetryPath: String) -> Never {
    guard securePrivateDirectory(applicationSupportPath, exactName: "Local Harness") else {
        fail("telemetry application-support root is unsafe")
    }
    let applicationSupport = URL(fileURLWithPath: applicationSupportPath, isDirectory: true)
    let telemetryDirectory = applicationSupport.appendingPathComponent("PerformanceTelemetry", isDirectory: true)
    guard securePrivateDirectory(telemetryDirectory.path, exactName: "PerformanceTelemetry") else {
        fail("telemetry directory is unsafe")
    }
    let expectedFile = telemetryDirectory.appendingPathComponent(telemetryFileName, isDirectory: false).path
    guard telemetryPath == expectedFile else { fail("telemetry file is outside the fixed storage boundary") }
    var telemetryMetadata = stat()
    guard lstat(telemetryPath, &telemetryMetadata) == 0,
          telemetryMetadata.st_mode & S_IFMT == S_IFREG,
          telemetryMetadata.st_uid == geteuid(),
          telemetryMetadata.st_nlink == 1,
          telemetryMetadata.st_mode & 0o777 == 0o600 else {
        fail("telemetry file is unsafe")
    }

    let lockPath = telemetryDirectory.appendingPathComponent(telemetryLockName, isDirectory: false).path
    var descriptor = open(lockPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
    if descriptor < 0, errno == ENOENT {
        descriptor = open(
            lockPath,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        if descriptor < 0, errno == EEXIST {
            descriptor = open(lockPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        }
    }
    guard descriptor >= 0 else { fail("telemetry lock could not be opened (\(errno))") }

    func lockPathMatchesDescriptor() -> Bool {
        var descriptorMetadata = stat()
        var pathMetadata = stat()
        return fstat(descriptor, &descriptorMetadata) == 0
            && lstat(lockPath, &pathMetadata) == 0
            && descriptorMetadata.st_mode & S_IFMT == S_IFREG
            && descriptorMetadata.st_uid == geteuid()
            && descriptorMetadata.st_nlink == 1
            && descriptorMetadata.st_mode & 0o777 == 0o600
            && pathMetadata.st_mode & S_IFMT == S_IFREG
            && pathMetadata.st_uid == geteuid()
            && pathMetadata.st_nlink == 1
            && pathMetadata.st_mode & 0o777 == 0o600
            && pathMetadata.st_dev == descriptorMetadata.st_dev
            && pathMetadata.st_ino == descriptorMetadata.st_ino
    }

    guard lockPathMatchesDescriptor() else {
        _ = close(descriptor)
        fail("telemetry lock is unsafe")
    }

    var acquired = false
    for attempt in 0..<250 {
        if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
            acquired = true
            break
        }
        guard errno == EWOULDBLOCK || errno == EAGAIN else {
            _ = close(descriptor)
            fail("telemetry lock failed")
        }
        if attempt < 249 { usleep(1_000) }
    }
    guard acquired else {
        FileHandle.standardOutput.write(Data("BUSY\n".utf8))
        _ = close(descriptor)
        exit(4)
    }
    guard lockPathMatchesDescriptor() else {
        _ = flock(descriptor, LOCK_UN)
        _ = close(descriptor)
        fail("telemetry lock changed while being acquired")
    }

    FileHandle.standardOutput.write(Data("LOCKED\n".utf8))
    var byte: UInt8 = 0
    while true {
        let count = Darwin.read(STDIN_FILENO, &byte, 1)
        if count == 0 { break }
        if count < 0, errno == EINTR { continue }
        if count < 0 {
            _ = flock(descriptor, LOCK_UN)
            _ = close(descriptor)
            fail("telemetry lock control pipe failed")
        }
        _ = flock(descriptor, LOCK_UN)
        _ = close(descriptor)
        fail("telemetry lock control pipe received unexpected data")
    }
    let unlocked = flock(descriptor, LOCK_UN) == 0
    let closed = close(descriptor) == 0
    guard unlocked, closed else { fail("telemetry lock could not be released") }
    exit(0)
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else { fail("expected a command") }
let command = arguments[1]

// Every unattended runtime credential operation crosses the mutually
// code-bound broker. The DSH descendant never receives a metadata-directory
// capability and this helper never performs those Keychain/metadata writes.
dispatchCredentialBrokerCommandIfNeeded(command: command, arguments: arguments)

if command == "backup-authorize-existing" {
    guard arguments.count == 2 else { fail("backup-authorize-existing takes no subject") }
    guard exactPackagedApplicationIsImmediateParent() else {
        fail("foreground credential authorization is unavailable")
    }
    runBackupAuthenticationKeyForegroundAuthorization()
}
if ["authorize", "repair-adopt", "repair-replace", "repair-remove", "authorize-record", "repair-adopt-record", "repair-remove-record"].contains(command) {
    guard arguments.count == 3 else { fail("foreground credential repair expects one reference") }
    guard exactPackagedApplicationIsImmediateParent() else {
        fail("foreground credential repair is unavailable")
    }
    runForegroundCredentialOperation(command: command, subject: arguments[2])
}

// Security.framework's modern per-query no-interaction context does not cover
// every legacy generic-password ACL prompt. This helper performs exactly one
// bounded operation, so disable Keychain UI process-wide as a second fail-closed
// barrier. Resolve the long-standing Security symbol dynamically to keep the
// warning-clean macOS 15+ build free of the deprecated Swift declaration.
guard let securityHandle = dlopen(
    "/System/Library/Frameworks/Security.framework/Security",
    RTLD_LAZY | RTLD_LOCAL
), let interactionSymbol = dlsym(securityHandle, "SecKeychainSetUserInteractionAllowed") else {
    fail("Keychain non-interactive mode is unavailable")
}
typealias KeychainInteractionSetter = @convention(c) (UInt8) -> OSStatus
let setKeychainInteraction = unsafeBitCast(interactionSymbol, to: KeychainInteractionSetter.self)
guard setKeychainInteraction(0) == errSecSuccess else {
    fail("Keychain non-interactive mode could not be enabled")
}

if command == "backup-load-or-create" {
    guard arguments.count == 2 else { fail("backup-load-or-create takes no subject") }
    runBackupAuthenticationKeyLoadOrCreate()
}
if command == "telemetry-lock" {
    guard arguments.count == 4 else { fail("telemetry-lock expects the application-support root and telemetry file") }
    runTelemetryLock(applicationSupportPath: arguments[2], telemetryPath: arguments[3])
}
if command == "list-records" {
    guard arguments.count == 2 else { fail("list-records takes no subject") }
    FileHandle.standardOutput.write(listRecordMetadata())
    exit(0)
}
if command == "list-record-attention" {
    guard arguments.count == 2 else { fail("list-record-attention takes no subject") }
    FileHandle.standardOutput.write(listRecordAttention())
    exit(0)
}
if command == "modify-record-locked" {
    guard arguments.count == 3 else { fail("modify-record-locked expects one record key") }
    runLockedRecordModification(subject: arguments[2])
}
guard arguments.count == 3 else { fail("expected command and credential subject") }
let subject = arguments[2]
let keychainAccount = account(for: command, subject: subject)

switch command {
case "get", "get-record":
    do {
        guard let data = try credentialCoordinator().readConfiguredValue(account: keychainAccount) else { exit(3) }
        FileHandle.standardOutput.write(data)
    } catch {
        failCredentialTransaction(error, operation: "read")
    }
case "describe", "describe-record":
    do {
        // Routine catalogue refresh is deliberately metadata-only. Reading
        // the Keychain value here makes every ad-hoc development-signature
        // change surface as an authorization failure while the app is merely
        // opening Models & Providers. Pending journals still recover through
        // `metadata(account:)`, where a bounded noninteractive value read is
        // required; ordinary committed markers never touch Keychain bytes.
        let coordinator = credentialCoordinator()
        let metadata = try coordinator.metadata(account: keychainAccount)
        if let metadata {
            let validKind = command == "describe-record"
                ? metadata.kind == "api-key" || metadata.kind == "grant"
                : metadata.kind == "reference"
            guard validKind else {
                fail("credential record is invalid", status: unsafeStateExitStatus)
            }
        }
        let configured = metadata != nil
        FileHandle.standardOutput.write(Data(configured ? "1".utf8 : "0".utf8))
    } catch {
        failCredentialTransaction(error, operation: "description")
    }
case "set", "set-record":
    let value = readBoundedCredentialInput()
    var kind = "reference"
    if command == "set-record" {
        guard let record = validatedRecord(value) else { fail("invalid credential record") }
        kind = record.kind
    }
    do {
        try credentialCoordinator().store(account: keychainAccount, value: value, kind: kind)
    } catch {
        failCredentialTransaction(error, operation: "write")
    }
case "unset", "unset-record":
    do {
        try credentialCoordinator().remove(account: keychainAccount)
    } catch {
        failCredentialTransaction(error, operation: "delete")
    }
default:
    fail("unknown command")
}
