import Darwin
import CryptoKit
import Foundation

enum ProviderCredentialRecoveryFailure: LocalizedError, Equatable, Sendable {
    case unavailable
    case timedOut
    case authorizationRequired
    case persistentAuthorizationRequired
    case recoveryRequired
    case busy
    case unsafeState
    case persistenceUnavailable
    case verificationFailed
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .unavailable:
            "The signed credential repair component is unavailable. Reinstall Fulmar."
        case .timedOut:
            "Credential repair timed out without changing the selected provider."
        case .authorizationRequired:
            "macOS did not authorize the exact existing credential. Try again and approve the Keychain prompt."
        case .persistentAuthorizationRequired:
            "The Keychain action may have committed, but a fresh noninteractive helper still cannot access the item. Choose Authorize Existing again and grant persistent access (for example, Always Allow)."
        case .recoveryRequired:
            "An interrupted or externally changed credential still needs an explicit recovery choice."
        case .busy:
            "Another credential operation is still finishing. Wait a moment and try again."
        case .unsafeState:
            "Credential state failed its ownership or integrity checks. No Keychain value was changed."
        case .persistenceUnavailable:
            "Credential recovery state could not be saved safely. No further change was attempted."
        case .verificationFailed:
            "The final Keychain value could not be verified. Recovery remains fail-closed."
        case .invalidResponse:
            "The credential repair component returned an invalid response."
        }
    }
}

enum ProviderRecordCredentialAttentionReason: String, Codable, Equatable, Sendable {
    case authorization
    case ambiguous
    case invalid
}

struct ProviderRecordCredentialAttention: Codable, Equatable, Sendable {
    let key: String
    let kind: String
    let reason: ProviderRecordCredentialAttentionReason
    let token: String
}

protocol ProviderCredentialRecoveryServicing: Sendable {
    func authorizeExisting(_ reference: CredentialReference) async throws
    func adoptCurrent(_ reference: CredentialReference) async throws
    func replaceCurrent(_ reference: CredentialReference, value: String) async throws
    func removeCurrent(_ reference: CredentialReference) async throws
    func listRecordAttention() async throws -> [ProviderRecordCredentialAttention]
    func authorizeRecord(_ key: String) async throws
    func adoptCurrentRecord(_ key: String) async throws
    func removeCurrentRecord(_ key: String) async throws
}

actor ProviderCredentialRecoveryClient: ProviderCredentialRecoveryServicing {
    struct Components: Sendable {
        let helper: URL
        let enforceIdentity: Bool
        init(helper: URL, enforceIdentity: Bool = false) {
            self.helper = helper
            self.enforceIdentity = enforceIdentity
        }
    }
    private struct PinnedComponents: Sendable {
        let components: Components
        let device: UInt64?
        let inode: UInt64?
        let sha256: String?
    }
    typealias ComponentLocator = @Sendable () throws -> Components
    typealias ProcessRunner = @Sendable (
        _ executable: URL,
        _ arguments: [String],
        _ environment: [String: String],
        _ input: Data?,
        _ outputLimit: Int,
        _ errorLimit: Int,
        _ deadline: TimeInterval
    ) throws -> CredentialMigrationProcessResult

    private static let deadline: TimeInterval = 120
    private static let maximumResponseBytes = 16
    private static let maximumDiagnosticBytes = 4 * 1_024
    private static let maximumAttentionBytes = 3 * 1_024 * 1_024
    private let componentLocator: ComponentLocator?
    private let processRunner: ProcessRunner
    private var recordAttentionTokens: [String: String] = [:]

    init(
        componentLocator: ComponentLocator? = nil,
        processRunner: @escaping ProcessRunner = {
            executable, arguments, environment, input, output, error, deadline in
            try BoundedCredentialMigrationProcess.run(
                executable: executable,
                arguments: arguments,
                environment: environment,
                standardInput: input,
                maximumStandardOutputBytes: output,
                maximumStandardErrorBytes: error,
                deadline: deadline
            )
        }
    ) {
        self.componentLocator = componentLocator
        self.processRunner = processRunner
    }

    func authorizeExisting(_ reference: CredentialReference) throws {
        let pinned = try pinComponents()
        try run(command: "authorize", reference: reference, input: nil, pinned: pinned)
        try verifyFreshAccess(reference, configured: true, pinned: pinned)
    }

    func adoptCurrent(_ reference: CredentialReference) throws {
        let pinned = try pinComponents()
        try run(command: "repair-adopt", reference: reference, input: nil, pinned: pinned)
        try verifyFreshAccess(reference, configured: true, pinned: pinned)
    }

    func replaceCurrent(_ reference: CredentialReference, value: String) throws {
        let bytes = Data(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 32 * 1_024,
              !value.unicodeScalars.contains(where: CharacterSet.newlines.contains) else {
            throw ProviderCredentialRecoveryFailure.invalidResponse
        }
        let pinned = try pinComponents()
        try run(command: "repair-replace", reference: reference, input: bytes, pinned: pinned)
        try verifyFreshAccess(reference, configured: true, pinned: pinned)
    }

    func removeCurrent(_ reference: CredentialReference) throws {
        let pinned = try pinComponents()
        try run(command: "repair-remove", reference: reference, input: nil, pinned: pinned)
        try verifyFreshAccess(reference, configured: false, pinned: pinned)
    }

    func listRecordAttention() throws -> [ProviderRecordCredentialAttention] {
        let pinned: PinnedComponents
        do { pinned = try pinComponents() }
        catch { throw ProviderCredentialRecoveryFailure.unavailable }
        let result: CredentialMigrationProcessResult
        do {
            result = try processRunner(
                pinned.components.helper,
                ["list-record-attention"],
                ChildProcessEnvironment.make(nodeBin: nil),
                nil,
                Self.maximumAttentionBytes,
                Self.maximumDiagnosticBytes,
                Self.deadline
            )
        } catch { throw ProviderCredentialRecoveryFailure.unavailable }
        try revalidate(pinned)
        try validateTransport(result)
        guard result.exitStatus == 0 else {
            try throwForStatus(result.exitStatus)
        }
        guard let raw = try? JSONSerialization.jsonObject(with: result.standardOutput),
              let rows = raw as? [[String: Any]], rows.count <= 4_096,
              rows.allSatisfy({ row in
                  Set(row.keys) == Set(["key", "kind", "reason", "token"])
                      && row["key"] is String && row["kind"] is String
                      && row["reason"] is String && row["token"] is String
              }),
              let decoded = try? JSONDecoder().decode(
            [ProviderRecordCredentialAttention].self,
            from: result.standardOutput
        ),
              Set(decoded.map(\.key)).count == decoded.count,
              decoded.allSatisfy({
                  Self.validRecordKey($0.key) && Self.validAttentionKind($0)
                      && $0.token.count == 64 && $0.token.allSatisfy(\.isHexDigit)
              }) else {
            throw ProviderCredentialRecoveryFailure.invalidResponse
        }
        recordAttentionTokens = Dictionary(uniqueKeysWithValues: decoded.map { ($0.key, $0.token) })
        return decoded.sorted { $0.key < $1.key }
    }

    private static func validAttentionKind(_ attention: ProviderRecordCredentialAttention) -> Bool {
        switch attention.kind {
        case "api-key", "grant": true
        case "unknown": attention.reason == .invalid
        default: false
        }
    }

    func authorizeRecord(_ key: String) throws {
        let pinned = try pinComponents()
        try runRecord(command: "authorize-record", key: key, pinned: pinned)
        try verifyFreshRecordAccess(key, configured: true, pinned: pinned)
    }

    func adoptCurrentRecord(_ key: String) throws {
        let pinned = try pinComponents()
        try runRecord(command: "repair-adopt-record", key: key, pinned: pinned)
        try verifyFreshRecordAccess(key, configured: true, pinned: pinned)
    }

    func removeCurrentRecord(_ key: String) throws {
        guard let token = recordAttentionTokens[key] else {
            throw ProviderCredentialRecoveryFailure.recoveryRequired
        }
        let pinned = try pinComponents()
        try runRecord(command: "repair-remove-record", key: key, input: Data(token.utf8), pinned: pinned)
        try verifyFreshRecordAccess(key, configured: false, pinned: pinned)
        recordAttentionTokens[key] = nil
    }

    private func verifyFreshRecordAccess(_ key: String, configured: Bool, pinned: PinnedComponents) throws {
        try runRecord(
            command: "describe-record",
            key: key,
            expectedOutput: Data((configured ? "1" : "0").utf8),
            authorizationFailure: .persistentAuthorizationRequired,
            pinned: pinned
        )
    }

    private func runRecord(
        command: String,
        key: String,
        input: Data? = nil,
        expectedOutput: Data = Data("OK\n".utf8),
        authorizationFailure: ProviderCredentialRecoveryFailure = .authorizationRequired
        , pinned: PinnedComponents? = nil
    ) throws {
        guard Self.validRecordKey(key) else { throw ProviderCredentialRecoveryFailure.invalidResponse }
        try run(
            command: command,
            subject: key,
            input: input,
            expectedOutput: expectedOutput,
            authorizationFailure: authorizationFailure,
            pinned: pinned
        )
    }

    private static func validRecordKey(_ key: String) -> Bool {
        key.utf8.count <= 512
            && key.range(
                of: #"^[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+$"#,
                options: .regularExpression
            ) != nil
    }

    private func verifyFreshAccess(_ reference: CredentialReference, configured: Bool, pinned: PinnedComponents) throws {
        try run(
            command: "describe",
            reference: reference,
            input: nil,
            expectedOutput: Data((configured ? "1" : "0").utf8),
            authorizationFailure: .persistentAuthorizationRequired,
            pinned: pinned
        )
    }

    private func run(
        command: String,
        reference: CredentialReference,
        input: Data?,
        expectedOutput: Data = Data("OK\n".utf8),
        authorizationFailure: ProviderCredentialRecoveryFailure = .authorizationRequired
        , pinned: PinnedComponents? = nil
    ) throws {
        try run(
            command: command,
            subject: reference.rawValue,
            input: input,
            expectedOutput: expectedOutput,
            authorizationFailure: authorizationFailure,
            pinned: pinned
        )
    }

    private func run(
        command: String,
        subject: String,
        input: Data?,
        expectedOutput: Data,
        authorizationFailure: ProviderCredentialRecoveryFailure,
        pinned suppliedPinned: PinnedComponents? = nil
    ) throws {
        let pinned: PinnedComponents
        do { pinned = try suppliedPinned ?? pinComponents() }
        catch { throw ProviderCredentialRecoveryFailure.unavailable }
        try revalidate(pinned)
        let result: CredentialMigrationProcessResult
        do {
            result = try processRunner(
                pinned.components.helper,
                [command, subject],
                ChildProcessEnvironment.make(nodeBin: nil),
                input,
                Self.maximumResponseBytes,
                Self.maximumDiagnosticBytes,
                Self.deadline
            )
        } catch {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
        try revalidate(pinned)
        try validateTransport(result)
        switch result.exitStatus {
        case 0:
            guard result.standardOutput == expectedOutput else {
                throw ProviderCredentialRecoveryFailure.invalidResponse
            }
        case 5: throw authorizationFailure
        case 6: throw ProviderCredentialRecoveryFailure.recoveryRequired
        case 7: throw ProviderCredentialRecoveryFailure.busy
        case 8: throw ProviderCredentialRecoveryFailure.unsafeState
        case 9: throw ProviderCredentialRecoveryFailure.persistenceUnavailable
        case 10: throw ProviderCredentialRecoveryFailure.verificationFailed
        default: throw ProviderCredentialRecoveryFailure.invalidResponse
        }
    }

    private func validateTransport(_ result: CredentialMigrationProcessResult) throws {
        if let limit = result.limit {
            if case .deadline = limit { throw ProviderCredentialRecoveryFailure.timedOut }
            throw ProviderCredentialRecoveryFailure.invalidResponse
        }
        guard result.terminationSignal == nil else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
    }

    private func throwForStatus(_ status: Int32?) throws -> Never {
        switch status {
        case 5: throw ProviderCredentialRecoveryFailure.authorizationRequired
        case 6: throw ProviderCredentialRecoveryFailure.recoveryRequired
        case 7: throw ProviderCredentialRecoveryFailure.busy
        case 8: throw ProviderCredentialRecoveryFailure.unsafeState
        case 9: throw ProviderCredentialRecoveryFailure.persistenceUnavailable
        case 10: throw ProviderCredentialRecoveryFailure.verificationFailed
        default: throw ProviderCredentialRecoveryFailure.invalidResponse
        }
    }

    private func locateComponents() throws -> Components {
        let manager = FileManager.default
        if let directory = Bundle.main.executableURL?.deletingLastPathComponent() {
            let helper = directory.appendingPathComponent("LocalHarnessCredentialHelper")
            if manager.isExecutableFile(atPath: helper.path) {
                return Components(helper: helper, enforceIdentity: true)
            }
        }
        guard Bundle.main.bundleURL.pathExtension != "app" else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
        let project = URL(fileURLWithPath: manager.currentDirectoryPath, isDirectory: true)
        let helper = project.appendingPathComponent(".build/debug/LocalHarnessCredentialHelper")
        guard manager.isExecutableFile(atPath: helper.path) else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
        return Components(helper: helper, enforceIdentity: true)
    }

    private func pinComponents() throws -> PinnedComponents {
        let components = try componentLocator?() ?? locateComponents()
        // Injected locators are a test seam. Production discovery is always
        // constrained to the executable directory and fully inode-pinned.
        guard components.enforceIdentity else {
            return PinnedComponents(components: components, device: nil, inode: nil, sha256: nil)
        }
        let path = components.helper.standardizedFileURL.path
        guard components.helper.path == path,
              components.helper.resolvingSymlinksInPath().standardizedFileURL.path == path else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
        var info = stat()
        guard lstat(path, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              (info.st_uid == geteuid() || info.st_uid == 0),
              info.st_mode & 0o022 == 0,
              info.st_mode & S_IXUSR != 0,
              info.st_size > 0, info.st_size <= 64 * 1_024 * 1_024,
              let bytes = try? Data(contentsOf: components.helper, options: .mappedIfSafe) else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
        if Bundle.main.bundleURL.pathExtension == "app" {
            guard BundleIntegrityVerifier.verify() else {
                throw ProviderCredentialRecoveryFailure.unavailable
            }
        }
        return PinnedComponents(
            components: components,
            device: UInt64(truncatingIfNeeded: info.st_dev),
            inode: UInt64(info.st_ino),
            sha256: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        )
    }

    private func revalidate(_ pinned: PinnedComponents) throws {
        guard let device = pinned.device, let inode = pinned.inode,
              let expectedSHA256 = pinned.sha256 else { return }
        var info = stat()
        guard lstat(pinned.components.helper.path, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              (info.st_uid == geteuid() || info.st_uid == 0), info.st_mode & 0o022 == 0,
              info.st_size > 0, info.st_size <= 64 * 1_024 * 1_024,
              UInt64(truncatingIfNeeded: info.st_dev) == device, UInt64(info.st_ino) == inode,
              let bytes = try? Data(contentsOf: pinned.components.helper, options: .mappedIfSafe),
              SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expectedSHA256 else {
            throw ProviderCredentialRecoveryFailure.unavailable
        }
    }
}
