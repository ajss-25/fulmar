import Foundation
import LocalHarnessDeviceAttestation
import Security

final class LocalHarnessTestDeviceAttestationKeyStore: DeviceAttestationRecoverableKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    private var reads: [String] = []
    private var inserts: [String] = []
    private var deletes: [String] = []
    var deleteFailureAccount: String?
    private var readFailure: DeviceAttestationError?
    private var backing: LocalHarnessTestDeviceAttestationKeyStore?

    init() {}

    /// A view over another store's values that can be made to refuse reads,
    /// standing in for the production noninteractive Keychain store whose
    /// read is refused (`errSecInteractionNotAllowed`) or cancelled while the
    /// interactive store sees the same items.
    init(sharing backing: LocalHarnessTestDeviceAttestationKeyStore, readFailure: DeviceAttestationError?) {
        self.backing = backing
        self.readFailure = readFailure
    }

    func setReadFailure(_ failure: DeviceAttestationError?) {
        lock.lock()
        readFailure = failure
        lock.unlock()
    }

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        reads.append(account)
        if let readFailure { throw readFailure }
        if let backing { return try backing.read(account: account) }
        return values[account]
    }

    func insert(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if let backing {
            try backing.insert(data, account: account)
            inserts.append(account)
            return
        }
        guard values[account] == nil else {
            throw DeviceAttestationError.invalidConfiguration
        }
        values[account] = data
        inserts.append(account)
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if deleteFailureAccount == account {
            throw DeviceAttestationError.keychainFailure(errSecIO)
        }
        deletes.append(account)
        if let backing { try backing.delete(account: account); return }
        values.removeValue(forKey: account)
    }

    func removeForTest(account: String) {
        lock.lock()
        values.removeValue(forKey: account)
        lock.unlock()
    }

    func resetObservations() {
        lock.lock()
        reads.removeAll()
        inserts.removeAll()
        deletes.removeAll()
        lock.unlock()
    }

    func observations() -> (reads: [String], inserts: [String], deletes: [String]) {
        lock.lock()
        defer { lock.unlock() }
        return (reads, inserts, deletes)
    }
}
