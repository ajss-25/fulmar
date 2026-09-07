import CryptoKit
import Darwin
import Foundation
import Security
@_spi(Testing) import LocalHarnessDeviceAttestation

private enum TestFailure: Error { case failed(String) }
private func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw TestFailure.failed(message) }
}
private func expectThrows(_ expected: DeviceAttestationError, _ body: () throws -> Void) throws {
    do { try body(); throw TestFailure.failed("expected \(expected)") }
    catch let actual as DeviceAttestationError {
        guard actual == expected else { throw TestFailure.failed("expected \(expected), got \(actual)") }
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0
    func increment() { lock.lock(); stored += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return stored }
}

/// Records every policy primitive call and every wrapped operation invocation,
/// so a scenario can prove exactly which native steps ran and which did not.
/// The operation is a counted stub: no Keychain call is made anywhere here.
private final class InteractionPolicyLedger: @unchecked Sendable {
    private let lock = NSLock()
    private var storedGets = 0
    private var storedSets: [UInt8] = []
    private var storedOperations = 0

    /// Policy value reported by a successful `get`.
    var previousPolicy: UInt8 = 1
    /// Status returned by `get`.
    var getStatus: OSStatus = errSecSuccess
    /// Statuses returned by successive `set` calls; the last entry repeats.
    var setStatuses: [OSStatus] = [errSecSuccess]

    func reset() {
        lock.lock()
        storedGets = 0
        storedSets.removeAll()
        storedOperations = 0
        lock.unlock()
    }

    func runOperation() -> OSStatus {
        lock.lock()
        storedOperations += 1
        lock.unlock()
        return errSecSuccess
    }

    var gets: Int { lock.lock(); defer { lock.unlock() }; return storedGets }
    var sets: [UInt8] { lock.lock(); defer { lock.unlock() }; return storedSets }
    var operations: Int { lock.lock(); defer { lock.unlock() }; return storedOperations }

    var primitives: LegacyKeychainInteraction.Primitives {
        LegacyKeychainInteraction.Primitives(
            get: { [self] pointer in
                lock.lock()
                storedGets += 1
                let status = getStatus
                if status == errSecSuccess { pointer.pointee = previousPolicy }
                lock.unlock()
                return status
            },
            set: { [self] value in
                lock.lock()
                storedSets.append(value)
                let index = min(storedSets.count - 1, setStatuses.count - 1)
                let status = setStatuses[index]
                lock.unlock()
                return status
            },
            status: { _, pointer in pointer.pointee = 1; return errSecSuccess }
        )
    }
}
private final class MemoryKeyStore: DeviceAttestationRecoverableKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    var values: [String: Data]
    var reads: [String] = []
    var inserts: [String] = []
    var deletes: [String] = []
    var failure: DeviceAttestationError?
    var insertFailureAccount: String?
    var deleteFailureAccount: String?
    init(_ values: [String: Data] = [:]) { self.values = values }
    func read(account: String) throws -> Data? {
        try lock.withLock { reads.append(account); if let failure { throw failure }; return values[account] }
    }
    func insert(_ data: Data, account: String) throws {
        try lock.withLock {
            if let failure { throw failure }
            if insertFailureAccount == account { throw DeviceAttestationError.keychainFailure(errSecIO) }
            guard values[account] == nil else { throw DeviceAttestationError.keychainFailure(errSecDuplicateItem) }
            values[account] = data; inserts.append(account)
        }
    }
    func delete(account: String) throws {
        try lock.withLock {
            if let failure { throw failure }
            if deleteFailureAccount == account { throw DeviceAttestationError.keychainFailure(errSecIO) }
            values.removeValue(forKey: account)
            deletes.append(account)
        }
    }
    func resetObservations() { lock.withLock { reads = []; inserts = []; deletes = [] } }
}

/// Stands in for a legacy login-keychain read that blocks on a SecurityAgent
/// prompt before returning the item: the read succeeds, but only after `delay`.
private struct SlowKeyStore: DeviceAttestationKeyStore {
    let backing: MemoryKeyStore
    let delay: TimeInterval
    func read(account: String) throws -> Data? {
        usleep(UInt32(delay * 1_000_000))
        return try backing.read(account: account)
    }
    func insert(_ data: Data, account: String) throws { try backing.insert(data, account: account) }
}

private struct Fixture {
    let root: URL
    let configuration: DeviceAttestationAuthority.Configuration
    init() throws {
        // The attestation path deliberately refuses a world-writable ancestor
        // such as /private/tmp. Resolve the account home from the OS identity,
        // not HOME/CFFIXED_USER_HOME supplied by a hostile or isolated runner,
        // and keep the UUID fixture in the owner-private Caches directory.
        guard let account = getpwuid(geteuid()), let homePointer = account.pointee.pw_dir else {
            throw TestFailure.failed("account home unavailable")
        }
        let canonicalTemporary = URL(fileURLWithPath: String(cString: homePointer), isDirectory: true)
            .appendingPathComponent("Library/Caches", isDirectory: true)
        let candidateRoot = canonicalTemporary.appendingPathComponent(
            "fulmar-device-attestation-\(UUID().uuidString)",
            isDirectory: true
        )
        do {
            try FileManager.default.createDirectory(
                at: candidateRoot,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: candidateRoot.path
            )
        } catch {
            try? FileManager.default.removeItem(at: candidateRoot)
            throw error
        }
        root = candidateRoot
        configuration = .init(controlParent: candidateRoot)
    }
    var control: URL { root.appendingPathComponent(".FulmarControl/DeviceAttestation", isDirectory: true) }
    func privateDirectory(_ name: String) throws -> URL {
        let result = root.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: result.path)
        return result
    }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

@main private struct DeviceAttestationAuthorityTests {
    static func main() throws {
        try run("envelope", envelopeSchemaTamperAndDomain)
        try run("background", backgroundAnchorOnly)
        try run("preplant", preplantAndHalfState)
        try run("bootstrap-recovery", explicitBootstrapRecovery)
        try run("path", pathSymlinkModeAndACL)
        try run("publication", preparedRenameCurrentOpaqueRoot)
        try run("crash", everyCrashWindow)
        try run("tamper", markerTamperAndDeadline)
        try run("harness-home", harnessHomeCapabilityTamperSwapAndCrash)
        try run("harness-home-rotation", harnessHomeRotationCrashRecovery)
        try run("keychain-authorization", keychainPromptDeadlineAndExplicitAuthorization)
        try run("interaction-policy", boundedInteractionPolicyAdmissionAndPolicyFailures)
        print("DeviceAttestationAuthorityTests: 12 passed")
    }

    /// The process-wide interaction policy is a shared resource: an open
    /// foreground prompt holds it. A background access must give up inside its
    /// own bound instead of spending the caller's operation deadline; a policy
    /// whose existing value cannot be read, or which cannot be established,
    /// must not run the Keychain call at all; and a user-initiated access whose
    /// policy cannot be returned to fail-closed must discard its result rather
    /// than leave the process able to prompt.
    ///
    /// Every case below substitutes both the policy primitives and the wrapped
    /// operation, so the real Keychain is never reached and invocation or
    /// non-invocation is proved by counters rather than by an absent item.
    static func boundedInteractionPolicyAdmissionAndPolicyFailures() throws {
        let ledger = InteractionPolicyLedger()
        let background = MacOSDeviceAttestationKeychain(
            service: "com.angadjairath.localharness.device-attestation.test-policy",
            accessGroup: nil,
            interaction: .forbidden,
            admissionBound: 0.05
        )
        let foreground = MacOSDeviceAttestationKeychain(
            service: "com.angadjairath.localharness.device-attestation.test-policy",
            accessGroup: nil,
            interaction: .userInitiated,
            admissionBound: 0.05
        )
        func runBackground() throws -> OSStatus {
            try background.runThroughInteractionPolicyForTesting { ledger.runOperation() }
        }
        func runForeground() throws -> OSStatus {
            try foreground.runThroughInteractionPolicyForTesting { ledger.runOperation() }
        }

        // Contention: the policy is held exactly as an open native prompt holds
        // it. Both bounded admissions fail closed inside their bound, and
        // neither reads the policy, writes it, or runs the operation.
        let held = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let holder = Thread {
            LegacyKeychainInteraction.acquirePolicyForTesting()
            held.signal()
            release.wait()
            LegacyKeychainInteraction.releasePolicyForTesting()
        }
        holder.start()
        guard held.wait(timeout: .now() + 5) == .success else {
            throw TestFailure.failed("the policy holder never started")
        }
        try LegacyKeychainInteraction.withPrimitivesForTesting(ledger.primitives) {
            let started = Date()
            try expectThrows(.keychainInteractionUnavailable(.contended)) { _ = try runBackground() }
            let waited = Date().timeIntervalSince(started)
            try expect(waited < 2, "a bounded background admission waited \(waited)s behind the policy")
            try expectThrows(.keychainInteractionUnavailable(.contended)) { _ = try runForeground() }
            try expect(ledger.gets == 0, "a contended admission read the policy")
            try expect(ledger.sets.isEmpty, "a contended admission wrote the policy")
            try expect(ledger.operations == 0, "a contended admission ran the Keychain operation")
        }
        release.signal()
        while !holder.isFinished { usleep(1_000) }

        // The existing policy cannot be read. Nothing may be written on top of
        // an unknown value and nothing may be executed under it.
        ledger.reset()
        ledger.getStatus = errSecNotAvailable
        ledger.setStatuses = [errSecSuccess]
        try LegacyKeychainInteraction.withPrimitivesForTesting(ledger.primitives) {
            try expectThrows(.keychainInteractionUnavailable(.unavailable)) { _ = try runBackground() }
            try expectThrows(.keychainInteractionUnavailable(.unavailable)) { _ = try runForeground() }
        }
        try expect(ledger.gets == 2, "an unreadable policy was not read exactly once per access")
        try expect(ledger.sets.isEmpty, "an unreadable policy was overwritten with a guessed value")
        try expect(ledger.operations == 0, "an unreadable policy still ran the Keychain operation")

        // Setup failure: the policy is readable but cannot be established, so
        // the call is never made and nothing is reported as a permission
        // decision. Exactly one write is attempted and none is restored.
        ledger.reset()
        ledger.getStatus = errSecSuccess
        ledger.previousPolicy = 1
        ledger.setStatuses = [errSecNotAvailable]
        try LegacyKeychainInteraction.withPrimitivesForTesting(ledger.primitives) {
            try expectThrows(.keychainInteractionUnavailable(.unavailable)) { _ = try runBackground() }
            try expect(ledger.sets == [0], "a failed setup did not attempt exactly the fail-closed write")
            try expect(ledger.operations == 0, "a failed setup still ran the Keychain operation")
            ledger.reset()
            try expectThrows(.keychainInteractionUnavailable(.unavailable)) { _ = try runForeground() }
            try expect(ledger.sets == [1], "a failed setup did not attempt exactly the interactive write")
            try expect(ledger.operations == 0, "a failed setup still ran the Keychain operation")
        }

        // Restoration failure. The policy is applied, the operation runs, and
        // the restore fails. A forbidden access is left fail-closed, so its
        // status is honest and usable; a user-initiated one that cannot be
        // forced back to fail-closed discards its result instead. The restore
        // always carries the exact value that was read, never an invented one.
        ledger.reset()
        ledger.previousPolicy = 1
        ledger.setStatuses = [errSecSuccess, errSecNotAvailable]
        try LegacyKeychainInteraction.withPrimitivesForTesting(ledger.primitives) {
            let status = try runBackground()
            try expect(status == errSecSuccess, "the forbidden call did not run under a failed restore")
            try expect(ledger.operations == 1, "the forbidden operation did not run exactly once")
            try expect(
                ledger.sets == [0, 1],
                "a forbidden restore did not attempt exactly the policy value that was read"
            )
            ledger.reset()
            try expectThrows(.keychainInteractionUnavailable(.unavailable)) { _ = try runForeground() }
            try expect(ledger.operations == 1, "the user-initiated operation did not run exactly once")
            try expect(
                ledger.sets == [1, 1, 0],
                "a user-initiated access did not try to force the fail-closed policy back"
            )
        }

        // A previously disabled policy is restored to disabled, not to an
        // assumed enabled default.
        ledger.reset()
        ledger.previousPolicy = 0
        ledger.setStatuses = [errSecSuccess]
        try LegacyKeychainInteraction.withPrimitivesForTesting(ledger.primitives) {
            _ = try runForeground()
            try expect(ledger.sets == [1, 0], "a restored policy did not return the exact value read")
            try expect(ledger.operations == 1, "the restored path did not run its operation exactly once")
        }
    }

    /// Faithful reproduction of the owner-visible failure and the explicit
    /// authorization contract that replaces it. No live Keychain is touched.
    static func keychainPromptDeadlineAndExplicitAuthorization() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let keys = MemoryKeyStore()
        _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        let privateAccount = fixture.configuration.privateKeyAccount
        let anchorAccount = fixture.configuration.publicAnchorAccount

        // A "noninteractive" read that blocks on a permission prompt longer
        // than the operation deadline succeeds too late: the verifier reports
        // deadlineExceeded and the granted access is discarded. The same read
        // returning promptly verifies.
        let slow = SlowKeyStore(backing: keys, delay: 0.2)
        let short = DeviceAttestationAuthority.Configuration(controlParent: fixture.root, operationDuration: 0.05)
        try expectThrows(.deadlineExceeded) {
            _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: short, keyStore: slow)
        }
        _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys)

        // Explicit authorization is read-only and proves persistence through
        // the noninteractive store, never through the interactive one.
        let interactive = MemoryKeyStore(keys.values)
        try expect(try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
            configuration: fixture.configuration, interactiveStore: interactive, noninteractiveStore: keys
        ) == .persistent, "both stores readable is persistent")
        try expect(interactive.reads == [privateAccount, anchorAccount], "interactive read order")
        try expect(interactive.inserts.isEmpty && interactive.deletes.isEmpty, "authorization mutated the Keychain")
        let refused = MemoryKeyStore(keys.values); refused.failure = .keychainFailure(errSecInteractionNotAllowed)
        try expect(try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
            configuration: fixture.configuration, interactiveStore: interactive, noninteractiveStore: refused
        ) == .onceOnly, "a still-refused unattended read is once-only")
        let cancelled = MemoryKeyStore(keys.values); cancelled.failure = .keychainFailure(errSecUserCanceled)
        try expectThrows(.keychainFailure(errSecUserCanceled)) {
            _ = try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
                configuration: fixture.configuration, interactiveStore: cancelled, noninteractiveStore: keys
            )
        }
        try expect(cancelled.inserts.isEmpty, "cancellation mutated the Keychain")
        let missingPrivate = MemoryKeyStore([anchorAccount: keys.values[anchorAccount]!])
        try expectThrows(.privateKeyMissing) {
            _ = try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
                configuration: fixture.configuration, interactiveStore: missingPrivate, noninteractiveStore: keys
            )
        }
        let missingAnchor = MemoryKeyStore([privateAccount: keys.values[privateAccount]!])
        try expectThrows(.publicAnchorMissing) {
            _ = try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
                configuration: fixture.configuration, interactiveStore: missingAnchor, noninteractiveStore: keys
            )
        }
        try expect(missingPrivate.inserts.isEmpty && missingAnchor.inserts.isEmpty, "a missing half was created")
        let different = MemoryKeyStore(keys.values); different.values[anchorAccount] = Data(repeating: 1, count: 32)
        try expectThrows(.keyMaterialMismatch) {
            _ = try DeviceAttestationAuthority.authorizeExistingKeychainAccess(
                configuration: fixture.configuration, interactiveStore: interactive, noninteractiveStore: different
            )
        }

        // Status classification is content-free and distinguishes denial from
        // a pending permission or lock; other codes are reported verbatim.
        try expect(DeviceAttestationKeychainAccessProblem.classify(errSecAuthFailed) == .deniedOrCancelled, "auth failed")
        try expect(DeviceAttestationKeychainAccessProblem.classify(errSecUserCanceled) == .deniedOrCancelled, "user cancelled")
        try expect(DeviceAttestationKeychainAccessProblem.classify(errSecIO) == .other(errSecIO), "other status")
        let interaction = DeviceAttestationKeychainAccessProblem.classify(errSecInteractionNotAllowed)
        try expect(interaction == .authorizationRequired || interaction == .keychainLocked, "interaction not allowed")
    }

    static func run(_ name: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch { FileHandle.standardError.write(Data("FAILED \(name): \(error)\n".utf8)); throw error }
    }

    static func envelopeSchemaTamperAndDomain() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore())
        let envelope = try authority.sign(payload: Data("receipt".utf8), domain: "test.domain/a")
        try expect(try authority.verifier().verify(envelope, expectedDomain: "test.domain/a") == Data("receipt".utf8), "payload")
        try expectThrows(.wrongDomain) { _ = try authority.verifier().verify(envelope, expectedDomain: "test.domain/b") }
        guard var object = try JSONSerialization.jsonObject(with: envelope.encoded) as? [String: Any] else { throw TestFailure.failed("envelope JSON") }
        object["unexpected"] = true
        let extended = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try expectThrows(.malformedEnvelope) { _ = try authority.verifier().verify(.init(encoded: extended), expectedDomain: "test.domain/a") }
        object.removeValue(forKey: "unexpected"); object["payload"] = Data("tampered".utf8).base64EncodedString()
        let tampered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        try expectThrows(.invalidSignature) { _ = try authority.verifier().verify(.init(encoded: tampered), expectedDomain: "test.domain/a") }
    }

    static func backgroundAnchorOnly() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let keys = MemoryKeyStore()
        try expect(try ProviderHistoryNamespaceMarkerStore.backgroundState(
            namespaceName: "clean", expectedURL: fixture.root.appendingPathComponent("clean"), expectedPrivacyEpoch: 1,
            expectedReceipt: Data(),
            configuration: fixture.configuration, keyStore: keys) == .absent, "clean absent")
        try expect(keys.reads.isEmpty && keys.inserts.isEmpty, "absent background touched Keychain")
        _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        keys.resetObservations(); _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys)
        try expect(keys.reads == [fixture.configuration.publicAnchorAccount], "background queried private key")
        keys.values.removeValue(forKey: fixture.configuration.publicAnchorAccount)
        try expectThrows(.publicAnchorMissing) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        keys.failure = .keychainFailure(errSecInteractionNotAllowed)
        try expectThrows(.keychainFailure(errSecInteractionNotAllowed)) {
            _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys)
        }
    }

    static func preplantAndHalfState() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            try FileManager.default.createDirectory(at: fixture.control, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.root.appendingPathComponent(".FulmarControl").path)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.control.path)
            let file = fixture.control.appendingPathComponent(DeviceAttestationAuthority.publicKeyFileName)
            try Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            let keys = MemoryKeyStore()
            try expectThrows(.untrustedPreexistingPublicKey) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys) }
            try expect(keys.inserts.isEmpty, "preplant mutated Keychain")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let privateKey = Curve25519.Signing.PrivateKey(), wrongAnchor = Data(repeating: 0x5a, count: 32)
            let keys = MemoryKeyStore([fixture.configuration.privateKeyAccount: privateKey.rawRepresentation,
                                       fixture.configuration.publicAnchorAccount: wrongAnchor])
            try expectThrows(.keyMaterialMismatch) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys) }
            try expect(keys.values[fixture.configuration.publicAnchorAccount] == wrongAnchor && keys.inserts.isEmpty, "half-state replaced")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let plantedPrivate = Curve25519.Signing.PrivateKey().rawRepresentation
            let keys = MemoryKeyStore([fixture.configuration.privateKeyAccount: plantedPrivate])
            try expectThrows(.publicAnchorMissing) {
                _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            }
            try expect(keys.inserts.isEmpty, "private-only half-state was completed")
        }
    }

    static func explicitBootstrapRecovery() throws {
        // Simulate power loss after private-key insertion but before the public
        // anchor. Ordinary foreground open remains detection-only. Only an
        // explicit operation beneath DeviceTrustRecovery can reset the two
        // exact accounts and bootstrap a new generation.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            keys.insertFailureAccount = fixture.configuration.publicAnchorAccount
            try expectThrows(.keychainFailure(errSecIO)) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            keys.insertFailureAccount = nil
            try expect(keys.values[fixture.configuration.privateKeyAccount] != nil, "private half not retained")
            try expectThrows(.publicAnchorMissing) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-explicit", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            let state = try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                configuration: fixture.configuration
            )
            let authorization = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                configuration: fixture.configuration,
                recoveryOperationRoot: operation,
                expectedControlState: state
            )
            let repaired = try DeviceAttestationAuthority.recoverForeground(
                configuration: fixture.configuration,
                keyStore: keys,
                authorization: authorization
            )
            try expect(keys.deletes == [
                fixture.configuration.privateKeyAccount,
                fixture.configuration.publicAnchorAccount
            ], "recovery deleted an unexpected Keychain account")
            _ = try repaired.sign(payload: Data("new-generation".utf8), domain: "test.recovered")
            try expect(FileManager.default.fileExists(
                atPath: operation.appendingPathComponent("DeviceAttestationControl").path
            ), "old control namespace was not retained")
        }

        // A crash after exact account deletion is not mistaken for first run
        // while any recovery output exists. Explicit recovery can resume.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            _ = try fixture.privateDirectory(
                DeviceAttestationAuthority.recoveryGuardLeafName + "/operation-crashed"
            )
            try expectThrows(.bootstrapRecoveryRequired) {
                _ = try DeviceAttestationAuthority.openForeground(
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
            try expect(keys.inserts.isEmpty, "guarded recovery was bootstrapped automatically")
            try expect(FileManager.default.fileExists(atPath: recovery.path), "recovery guard disappeared")
        }

        // A stale confirmation cannot move a substituted control namespace.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            _ = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let expected = try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                configuration: fixture.configuration
            )
            let old = fixture.root.appendingPathComponent("old-control", isDirectory: true)
            try FileManager.default.moveItem(at: fixture.control, to: old)
            try FileManager.default.createDirectory(at: fixture.control, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.control.path)
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-stale", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            try expectThrows(.recoveryAuthorizationInvalid) {
                _ = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                    configuration: fixture.configuration,
                    recoveryOperationRoot: operation,
                    expectedControlState: expected
                )
            }
            try expect(keys.deletes.isEmpty, "stale control confirmation reached Keychain deletion")
        }

        // If either exact delete fails, bootstrap is not attempted and the
        // remaining half-state stays blocked for another explicit retry.
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore()
            _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let recovery = try fixture.privateDirectory(DeviceAttestationAuthority.recoveryGuardLeafName)
            let operation = recovery.appendingPathComponent("operation-delete-failure", isDirectory: true)
            try FileManager.default.createDirectory(at: operation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: operation.path)
            let authorization = try DeviceAttestationAuthority.authorizeBootstrapRecovery(
                configuration: fixture.configuration,
                recoveryOperationRoot: operation,
                expectedControlState: try DeviceAttestationAuthority.bootstrapRecoveryControlState(
                    configuration: fixture.configuration
                )
            )
            keys.deleteFailureAccount = fixture.configuration.publicAnchorAccount
            try expectThrows(.keychainFailure(errSecIO)) {
                _ = try DeviceAttestationAuthority.recoverForeground(
                    configuration: fixture.configuration,
                    keyStore: keys,
                    authorization: authorization
                )
            }
            try expect(keys.inserts.count == 2, "delete failure unexpectedly bootstrapped another key")
            try expect(keys.values[fixture.configuration.publicAnchorAccount] != nil, "failed anchor delete changed anchor")
        }
    }

    static func pathSymlinkModeAndACL() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let add = Process(); add.executableURL = URL(fileURLWithPath: "/bin/chmod")
            add.arguments = ["+a", "group:everyone deny delete", fixture.root.path]
            try add.run(); try expect(waitBounded(add, seconds: 2) && add.terminationStatus == 0, "deny ACL setup")
            _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore())
            let clear = Process(); clear.executableURL = URL(fileURLWithPath: "/bin/chmod"); clear.arguments = ["-N", fixture.root.path]
            try clear.run(); try expect(waitBounded(clear, seconds: 2) && clear.terminationStatus == 0, "deny ACL cleanup")
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let outside = try fixture.privateDirectory("outside")
            try FileManager.default.createSymbolicLink(at: fixture.root.appendingPathComponent(".FulmarControl"), withDestinationURL: outside)
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: MemoryKeyStore()) }
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore(); _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.control.path)
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        }
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let keys = MemoryKeyStore(); _ = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow read", fixture.control.path]; try process.run()
            try expect(waitBounded(process, seconds: 2) && process.terminationStatus == 0, "bounded chmod failed")
            try expectThrows(.unsafeControlPath) { _ = try DeviceAttestationAuthority.openBackgroundVerifier(configuration: fixture.configuration, keyStore: keys) }
        }
    }

    static func preparedRenameCurrentOpaqueRoot() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
        let historical = source.appendingPathComponent("Backups", isDirectory: true)
        try FileManager.default.createDirectory(at: historical, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expect(Darwin.mkfifo(historical.appendingPathComponent("must-not-open").path, 0o600) == 0, "fifo")
        let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        let store = authority.makeProviderHistoryNamespaceMarkerStore()
        let current = try store.publish(.init(
            sourceParent: source, sourceLeaf: "Backups", destinationParent: destination, destinationLeaf: "historical-backups",
            namespaceName: "provider-history-backups", privacyEpoch: 7, receipt: Data("exact receipt".utf8)))
        try expect(current.state == .current && current.privacyEpoch == 7, "current fields")
        var metadata = stat()
        try expect(Darwin.lstat(destination.appendingPathComponent("historical-backups/must-not-open").path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFIFO, "opaque child was not preserved")
        let expected = destination.appendingPathComponent("historical-backups")
        let migration = source.appendingPathComponent("Migration")
        try FileManager.default.createDirectory(at: migration, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let migrationCurrent = try store.publish(.init(
            sourceParent: source, sourceLeaf: "Migration", destinationParent: destination, destinationLeaf: "historical-migration",
            namespaceName: "provider-history-migration", privacyEpoch: 7, receipt: Data("migration receipt".utf8)))
        keys.resetObservations()
        let states = try ProviderHistoryNamespaceMarkerStore.backgroundStates([
            .init(namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                  expectedReceipt: Data("exact receipt".utf8)),
            .init(namespaceName: "provider-history-migration", expectedURL: destination.appendingPathComponent("historical-migration"), expectedPrivacyEpoch: 7,
                  expectedReceipt: Data("migration receipt".utf8))
        ], configuration: fixture.configuration, keyStore: keys)
        try expect(states["provider-history-backups"] == .current(current)
            && states["provider-history-migration"] == .current(migrationCurrent), "per-namespace batch")
        try expect(keys.reads == [fixture.configuration.publicAnchorAccount] && keys.inserts.isEmpty, "batch anchor count")
        try expectThrows(.namespaceChanged) {
            _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                expectedReceipt: Data("changed receipt".utf8), configuration: fixture.configuration, keyStore: keys)
        }
        try FileManager.default.createDirectory(at: source.appendingPathComponent("Backups2"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expectThrows(.foregroundRequired) {
            _ = try store.publish(.init(sourceParent: source, sourceLeaf: "Backups2", destinationParent: destination,
                destinationLeaf: "historical-backups-2", namespaceName: "provider-history-backups", privacyEpoch: 8,
                receipt: Data("new receipt".utf8)))
        }
        try expect(FileManager.default.fileExists(atPath: source.appendingPathComponent("Backups2").path), "current collision moved source")
        let displaced = destination.appendingPathComponent("displaced")
        try FileManager.default.moveItem(at: expected, to: displaced)
        try FileManager.default.createDirectory(at: expected, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try expectThrows(.namespaceChanged) {
            _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "provider-history-backups", expectedURL: expected, expectedPrivacyEpoch: 7,
                expectedReceipt: Data("exact receipt".utf8),
                configuration: fixture.configuration, keyStore: keys)
        }
    }

    static func everyCrashWindow() throws {
        for phase: ProviderHistoryNamespacePublicationPhase in [.preparedWritten, .rootRenamedAndSynced, .currentWritten] {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
            try FileManager.default.createDirectory(at: source.appendingPathComponent("History"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
            let store = ProviderHistoryNamespaceMarkerStore(authority: authority, interruption: { $0 == phase })
            try expectThrows(.injectedInterruption(phase)) {
                _ = try store.publish(.init(sourceParent: source, sourceLeaf: "History", destinationParent: destination,
                    destinationLeaf: "historical-history", namespaceName: "history", privacyEpoch: 9, receipt: Data("receipt".utf8)))
            }
            guard case .foregroundRequired = try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "history", expectedURL: source.appendingPathComponent("History"), expectedPrivacyEpoch: 9,
                expectedReceipt: Data("receipt".utf8),
                configuration: fixture.configuration, keyStore: keys) else { throw TestFailure.failed("prepared did not force foreground") }
            let current = try store.reconcilePrepared(namespaceName: "history")
            try expect(try ProviderHistoryNamespaceMarkerStore.backgroundState(
                namespaceName: "history", expectedURL: destination.appendingPathComponent("historical-history"), expectedPrivacyEpoch: 9,
                expectedReceipt: Data("receipt".utf8),
                configuration: fixture.configuration, keyStore: keys) == .current(current), "reconcile")
        }
    }

    static func markerTamperAndDeadline() throws {
        let fixture = try Fixture(); defer { fixture.cleanup() }
        let source = try fixture.privateDirectory("source"), destination = try fixture.privateDirectory("destination")
        try FileManager.default.createDirectory(at: source.appendingPathComponent("History"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let keys = MemoryKeyStore(), authority = try DeviceAttestationAuthority.openForeground(configuration: fixture.configuration, keyStore: keys)
        _ = try authority.makeProviderHistoryNamespaceMarkerStore().publish(.init(sourceParent: source, sourceLeaf: "History",
            destinationParent: destination, destinationLeaf: "old-history", namespaceName: "history", privacyEpoch: 3, receipt: Data("receipt".utf8)))
        let slot = Data(SHA256.hash(data: Data("history".utf8))).map { String(format: "%02x", $0) }.joined()
        let currentURL = fixture.control.appendingPathComponent(".namespace-\(slot).current")
        guard var envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: currentURL)) as? [String: Any],
              let payloadString = envelope["payload"] as? String,
              let payload = Data(base64Encoded: payloadString),
              var marker = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else { throw TestFailure.failed("marker JSON") }
        marker["leafName"] = "other"
        envelope["payload"] = try JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]).base64EncodedString()
        try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]).write(to: currentURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: currentURL.path)
        try expectThrows(.invalidSignature) { _ = try ProviderHistoryNamespaceMarkerStore.backgroundState(
            namespaceName: "history", expectedURL: destination.appendingPathComponent("old-history"), expectedPrivacyEpoch: 3,
            expectedReceipt: Data("receipt".utf8),
            configuration: fixture.configuration, keyStore: keys) }
        let second = try Fixture(); defer { second.cleanup() }
        let invalid = DeviceAttestationAuthority.Configuration(controlParent: second.root, operationDuration: .infinity)
        try expectThrows(.invalidConfiguration) { _ = try DeviceAttestationAuthority.openForeground(configuration: invalid, keyStore: MemoryKeyStore()) }
        try expect(!FileManager.default.fileExists(atPath: second.root.appendingPathComponent(".FulmarControl").path), "invalid deadline mutated")
    }

    static func harnessHomeCapabilityTamperSwapAndCrash() throws {
        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receipt = home.appendingPathComponent(".local-harness-home.json")
            try Data("exact-receipt".utf8).write(to: receipt)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
            let keys = MemoryKeyStore()
            guard case .absent = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                expectedPrivacyEpoch: 3,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("unpublished home was not absent") }
            try expect(keys.reads.isEmpty && keys.inserts.isEmpty, "absent home touched Keychain")

            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let capability = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                privacyEpoch: 3
            )
            try capability.withBorrowedDescriptor { descriptor in
                var metadata = stat()
                try expect(Darwin.fstat(descriptor, &metadata) == 0, "retained home descriptor")
                try expect(
                    capability.record.inode == UInt64(truncatingIfNeeded: metadata.st_ino),
                    "retained descriptor identity"
                )
            }
            keys.resetObservations()
            guard case .current(let backgroundCapability) = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receipt.lastPathComponent,
                expectedPrivacyEpoch: 3,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("signed home not current") }
            try expect(
                backgroundCapability.record == capability.record,
                "background capability changed"
            )
            try expect(
                keys.reads == [fixture.configuration.publicAnchorAccount] && keys.inserts.isEmpty,
                "background home queried more than public anchor"
            )

            try Data("changed-receipt".utf8).write(to: receipt, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receipt.path)
            try expectThrows(.namespaceChanged) {
                _ = try HarnessHomeAttestationStore.backgroundState(
                    rootURL: home,
                    receiptLeafName: receipt.lastPathComponent,
                    expectedPrivacyEpoch: 3,
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
        }

        do {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receiptName = ".local-harness-home.json"
            try Data("receipt".utf8).write(to: home.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: home.appendingPathComponent(receiptName).path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 4
            )
            let displaced = fixture.root.appendingPathComponent("displaced")
            try FileManager.default.moveItem(at: home, to: displaced)
            let replacement = try fixture.privateDirectory("HarnessHome")
            try Data("receipt".utf8).write(to: replacement.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: replacement.appendingPathComponent(receiptName).path
            )
            try expectThrows(.namespaceChanged) {
                _ = try HarnessHomeAttestationStore.backgroundState(
                    rootURL: replacement,
                    receiptLeafName: receiptName,
                    expectedPrivacyEpoch: 4,
                    configuration: fixture.configuration,
                    keyStore: keys
                )
            }
        }

        for phase: HarnessHomeAttestationPublicationPhase in [.preparedWritten, .currentWritten] {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let home = try fixture.privateDirectory("HarnessHome")
            let receiptName = ".local-harness-home.json"
            try Data("receipt-\(phase.rawValue)".utf8)
                .write(to: home.appendingPathComponent(receiptName))
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: home.appendingPathComponent(receiptName).path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            let crashing = HarnessHomeAttestationStore(
                authority: authority,
                interruption: { $0 == phase }
            )
            do {
                _ = try crashing.establishCurrent(
                    rootURL: home,
                    receiptLeafName: receiptName,
                    privacyEpoch: 5
                )
                throw TestFailure.failed("expected home interruption \(phase)")
            } catch DeviceAttestationError.harnessHomeInjectedInterruption(let actual) {
                try expect(actual == phase, "wrong home interruption")
            }
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("home crash was not foreground-required") }
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 5
            )
            guard case .current = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("home crash did not reconcile") }
        }
    }

    static func harnessHomeRotationCrashRecovery() throws {
        let phases: [HarnessHomeAttestationRotationPhase] = [
            .preparedWritten,
            .previousCurrentPreserved,
            .previousCurrentRemoved,
            .replacementCurrentWritten,
            .completionWritten
        ]
        for phase in phases {
            let fixture = try Fixture(); defer { fixture.cleanup() }
            let receiptName = ".local-harness-home.json"
            let home = try fixture.privateDirectory("HarnessHome")
            let oldReceipt = home.appendingPathComponent(receiptName)
            try Data("old-receipt".utf8).write(to: oldReceipt)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: oldReceipt.path
            )
            let keys = MemoryKeyStore()
            let authority = try DeviceAttestationAuthority.openForeground(
                configuration: fixture.configuration,
                keyStore: keys
            )
            _ = try authority.makeHarnessHomeAttestationStore().establishCurrent(
                rootURL: home,
                receiptLeafName: receiptName,
                privacyEpoch: 4
            )
            let operationID = UUID()
            let recovery = try fixture.privateDirectory("HarnessHomeRecovery")
            let staging = recovery.appendingPathComponent("repairing", isDirectory: true)
            try FileManager.default.createDirectory(
                at: staging,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let newReceipt = staging.appendingPathComponent(receiptName)
            try Data("new-receipt".utf8).write(to: newReceipt)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: newReceipt.path
            )
            let crashing = HarnessHomeAttestationStore(
                authority: authority,
                rotationInterruption: { $0 == phase }
            )
            let session = try crashing.makeRotationSession(
                rootURL: home,
                receiptLeafName: receiptName,
                targetPrivacyEpoch: 5
            )
            try session.begin(
                operationID: operationID,
                choice: .startClean,
                stagedRootURL: staging
            )
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("rotation intent admitted background work") }
            try expectThrows(.foregroundRequired) {
                _ = try crashing.establishCurrent(
                    rootURL: home,
                    receiptLeafName: receiptName,
                    privacyEpoch: 5
                )
            }

            var interrupted = false
            do {
                _ = try session.prepare(
                    operationID: operationID,
                    choice: .startClean,
                    stagedRootURL: staging
                )
            } catch DeviceAttestationError.harnessHomeRotationInjectedInterruption(let actual) {
                try expect(actual == phase, "wrong prepared rotation phase")
                interrupted = true
            }
            let historical = fixture.root.appendingPathComponent("historical-home", isDirectory: true)
            try FileManager.default.moveItem(at: home, to: historical)
            try FileManager.default.moveItem(at: staging, to: home)
            if !interrupted {
                do {
                    _ = try session.finalize(
                        operationID: operationID,
                        choice: .startClean
                    )
                } catch DeviceAttestationError.harnessHomeRotationInjectedInterruption(let actual) {
                    try expect(actual == phase, "wrong final rotation phase")
                    interrupted = true
                }
            }
            try expect(interrupted, "rotation phase did not interrupt: \(phase)")
            guard case .foregroundRequired = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("interrupted rotation admitted background work") }

            let resumedStore = authority.makeHarnessHomeAttestationStore()
            let resumed = try resumedStore.makeRotationSession(
                rootURL: home,
                receiptLeafName: receiptName,
                targetPrivacyEpoch: 5
            )
            _ = try resumed.finalize(
                operationID: operationID,
                choice: .startClean
            )
            guard case .current(let capability) = try HarnessHomeAttestationStore.backgroundState(
                rootURL: home,
                receiptLeafName: receiptName,
                expectedPrivacyEpoch: 5,
                configuration: fixture.configuration,
                keyStore: keys
            ) else { throw TestFailure.failed("rotation did not publish current") }
            try expect(capability.record.privacyEpoch == 5, "replacement epoch")
            let previous = fixture.control.appendingPathComponent(
                ".harness-home.previous-\(operationID.uuidString.lowercased())"
            )
            try expect(FileManager.default.fileExists(atPath: previous.path), "old current was not preserved")
        }
    }

    static func waitBounded(_ process: Process, seconds: TimeInterval) -> Bool {
        let duration = UInt64(seconds * 1_000_000_000)
        let start = DispatchTime.now().uptimeNanoseconds
        let (deadline, overflow) = start.addingReportingOverflow(duration)
        if overflow { process.terminate(); return false }
        while process.isRunning, DispatchTime.now().uptimeNanoseconds < deadline { usleep(10_000) }
        if process.isRunning { process.terminate(); return false }
        return true
    }
}
